/* Symbion SSL Proxy
 * Copyright (C) 2000-2005 Szilard Hajba
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

//#define VERSION "1.0.7"
#define MAX_CONNECTION 32
//#define CS_BUFFER_LEN 2
//#define SC_BUFFER_LEN 40
#define CS_BUFFER_LEN 2048
#define SC_BUFFER_LEN 8192
#define PEM_DIR "/etc/symbion"
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#define SLEEP_US 50000

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

int debug_flag=0;
int fg_flag=0;
int info_flag=0;
int log_flag=0;
int conn_timeout=0;
int max_conn=MAX_CONNECTION;
int cs_buflen=CS_BUFFER_LEN, sc_buflen=SC_BUFFER_LEN;
char *server_addr="0.0.0.0";
int server_port=443;
char *client_addr="localhost";
int client_port=80;
char *cert_file=PEM_DIR"/"CERT_FILE, *key_file=PEM_DIR"/"KEY_FILE;
char *cipher_list="HIGH";
char *chroot_dir=NULL, *set_uid=NULL;
char *verify_ca_file=NULL, *verify_ca_dir=NULL;
struct passwd *pass;

int server_socket;
SSL_CTX *server_ssl_ctx;
//X509 *ssl_public_cert;
//RSA *ssl_private_key;

int client_s_family=AF_INET;
struct sockaddr *client_sa;
struct sockaddr_in client_sa_in;
struct sockaddr_un client_sa_un;
int client_sa_len;

typedef enum {cs_disconnected, cs_accept, cs_connecting, cs_connected, cs_closing} ConnStatus;
typedef struct {
    ConnStatus stat;			// Status of the connection
    time_t event_t;			// Last event
    int server_sock;			// Server side socket id
    struct sockaddr_in server_sa;	// Server's socket address
    int server_sa_len;			// ^^^^^^^^^^^^^^^^^^^^^^^'s len
    SSL *ssl_conn;			// SSL connection structure pointer
    int client_sock;			// Client side socket id
    char *csbuf;			// Server side write buffer
    char *csbuf_b;			// Server side write buffer begin ptr
    char *csbuf_e;			// Server side write buffer end ptr
//    int c_end_req;			// Client requested connection close
    char *scbuf;			// Client side write buffer
    char *scbuf_b;			// Client side write buffer begin ptr
    char *scbuf_e;			// Client side write buffer end ptr
//    int s_end_req;			// Server requested connection close
} Conn;
Conn *conn=NULL;

void conn_close_client(Conn *conn);
void conn_close_server(Conn *conn);

void debug(char *format,...)
{
    if (debug_flag) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	putc('\n', stderr);
	va_end(args);
    }
}

void plog(int level, const char *format,...)
{
    char str[8192];
    va_list args;
    va_start(args, format);
    vsprintf(str, format, args);
    va_end(args);
    syslog(level, "%s\n", str);
    if (debug_flag) debug("LOG: %.256s", str);
}

void plog_ssl_error(SSL *ssl_conn, int ret, char *cls, int sock)
{
    int err=SSL_get_error(ssl_conn, ret);
    switch (err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	    break;
	case SSL_ERROR_SSL:
	    plog(LOG_ERR, "ERROR @%d %s: %s", sock, cls,
		    ERR_error_string(ERR_get_error(), NULL));
	    break;
	case SSL_ERROR_SYSCALL:
	    if (!ret) {
		plog(LOG_ERR, "ERROR @%d %s: Unexpected EOF", sock, cls);
	    } else {
		plog(LOG_ERR, "ERROR @%d %s: %s (errno=%d)", sock, cls, strerror(errno), errno);
	    }
	    break;
	case SSL_ERROR_ZERO_RETURN:
//	    plog(LOG_ERR, "ERROR @%d %s: Zero return", sock, cls);
	    break;
	default:
	    plog(LOG_ERR, "ERROR @%d %s: Unknown SSL error (SSL_get_error()=%d)", sock, cls, err);
	    break;
    }
}

void _sleep()
{
    struct timeval tv={0, SLEEP_US};
    select(0, NULL, NULL, NULL, &tv);
}

// ============================================== Server
int server_init(char *addr, int port, int maxconn)
{
    struct sockaddr_in server;
    long ipaddr;

    server_socket=socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket<0) {
	perror("socket()");
	exit(1);
    }
    server.sin_family=AF_INET;
    inet_pton(AF_INET, addr, &ipaddr);
    server.sin_addr.s_addr=ipaddr;
//    server.sin_addr.s_addr=htons(INADDR_ANY);
    server.sin_port=htons(port);
    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
	perror("bind()");
	exit(1);
    }
    listen(server_socket, maxconn);
    fcntl(server_socket, F_SETFL, O_NONBLOCK);
    return server_socket;
}

void server_done(void)
{
    int ci;
    shutdown(server_socket, 2);
    _sleep();
    close(server_socket);
    for (ci=0; ci<max_conn; ci++)
	if (conn[ci].stat==cs_accept && conn[ci].stat==cs_connected) {
	    conn_close_client(&conn[ci]);
	    conn_close_server(&conn[ci]);
	}
}

// ============================================== Server SSL
static RSA *tmp_rsa_cb(SSL *ssl, int export, int key_len)
{
    static RSA *rsa=NULL; 
    debug("Generating new RSA key.. (ex=%d, kl=%d)", export, key_len);
    if (export) {
	rsa=RSA_generate_key(key_len, RSA_F4, NULL, NULL);
    } else {
	plog(LOG_ERR, "ERROR tmp_rsa_callback(): Export not set");
    }
    return rsa;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    fprintf(stderr, "preverify: %d\n", preverify_ok);
    return preverify_ok;
}

void server_ssl_init(void)
{
//    FILE *f;
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    server_ssl_ctx=SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_cipher_list(server_ssl_ctx, cipher_list);
    if (!SSL_CTX_set_default_verify_paths(server_ssl_ctx))  {
	fprintf(stderr, "cannot set default path\n");
	exit(1);
    }

    if (!SSL_CTX_use_certificate_chain_file(server_ssl_ctx, cert_file)) {
	fprintf(stderr,"error reading certificate: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    if (!SSL_CTX_use_PrivateKey_file(server_ssl_ctx, key_file, SSL_FILETYPE_PEM)) {
	fprintf(stderr,"error reading private key: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    SSL_CTX_set_tmp_rsa_callback(server_ssl_ctx, tmp_rsa_cb);

    if (verify_ca_file || verify_ca_dir) {
/*
	STACK_OF(X509_NAME) *certs;
	certs=SSL_load_client_CA_file(verify_ca_file);
	if (certs) {
	    SSL_CTX_set_client_CA_list(server_ssl_ctx, certs);
	} else {
	    fprintf(stderr,"error reading client CA list: %.256s\n",
		    ERR_error_string(ERR_get_error(), NULL));
	    exit(1);
	}
*/
	SSL_CTX_load_verify_locations(server_ssl_ctx, verify_ca_file, verify_ca_dir);
	SSL_CTX_set_verify(server_ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, verify_callback);
    }

//    SSL_CTX_set_session_cache_mode(server_ssl_ctx, SSL_SESS_CACHE_OFF);
}

// ============================================== CLient
void client_init(char *addr, int port)
{
    if (port) { // TCP connection
	struct hostent *hp;
	client_sa_in.sin_family=AF_INET;
	hp=gethostbyname(addr);
	if (!hp) {
	    perror("gethostbyname()");
	    exit(1);
	}
	bcopy(hp->h_addr, &client_sa_in.sin_addr, hp->h_length);
	client_sa_in.sin_port=htons(port);
	client_sa=(struct sockaddr *)&client_sa_in;
	client_sa_len=sizeof(client_sa_in);
    } else { // UNIX domain socket
	client_sa_un.sun_family=AF_UNIX;
	if (addr) {
	    if (strlen(addr)>=sizeof(client_sa_un.sun_path)) {
		fprintf(stderr, "client_init(): client address too long (allowed: %d)\n",
			(int)sizeof(client_sa_un.sun_path));
		exit(1);
	    } else strcpy(client_sa_un.sun_path, addr);
	} else {
	    fprintf(stderr, "client_init(): client address missing\n");
	    exit(1);
	}
	client_sa=(struct sockaddr *)&client_sa_un;
	client_sa_len=sizeof(client_sa_un);
    }
}

// ============================================== Connection
struct sockaddr_in server_sa;
unsigned int server_sa_len;
int conn_accept(void)
{
    int i;
    // Initialize SSL connection (server side)
    int s=accept(server_socket, (struct sockaddr *)&server_sa, &server_sa_len);
    if (s<=0) return 0;
    debug("conn_accept(): Client connected");
    for (i=0; i<max_conn && conn[i].stat!=cs_disconnected; i++);
    if (i==max_conn) {
	plog(LOG_ERR, "ERROR accept(): No more connections allowed");
	close(s);
	return 0;
    }
    debug("accept(): sn=%d sock=%d", i, s);
    conn[i].server_sock=s;
    bcopy(&server_sa, &conn[i].server_sa, server_sa_len);
    conn[i].server_sa_len=server_sa_len;
    conn[i].ssl_conn=SSL_new(server_ssl_ctx);
    SSL_set_fd(conn[i].ssl_conn, conn[i].server_sock);
    BIO_set_nbio(SSL_get_rbio(conn[i].ssl_conn), 0);
    BIO_set_nbio(SSL_get_wbio(conn[i].ssl_conn), 0);
    fcntl(conn[i].server_sock, F_SETFL, O_NONBLOCK);
    conn[i].stat=cs_accept;
    conn[i].scbuf_b=conn[i].scbuf; conn[i].scbuf_e=conn[i].scbuf;
    conn[i].csbuf_b=conn[i].csbuf; conn[i].csbuf_e=conn[i].csbuf;
    return conn[i].server_sock;
}

int conn_ssl_accept(Conn *conn)
{
    int ret=SSL_accept(conn->ssl_conn);
//    debug("SSL_accept: %d, SSL_want=%d", ret, SSL_want(conn->ssl_conn));
    if (ret<=0) {
	unsigned long err=SSL_get_error(conn->ssl_conn, ret);
	if (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE) {
	    return 1;
	}

	plog_ssl_error(conn->ssl_conn, ret, "SSL_accept()", conn->server_sock);
//	ERR_print_errors_fp(stderr);
	SSL_free(conn->ssl_conn);
	close(conn->server_sock);
	conn->server_sock=conn->client_sock=0;
	conn->stat=cs_disconnected;
	return -1;
    }

    // Connect to server (client side)
    conn->client_sock=socket(client_s_family, SOCK_STREAM, 0);
    if (conn->client_sock<0) {
	plog(LOG_ERR, "ERROR socket(): %s", strerror(errno));
	SSL_free(conn->ssl_conn);
	close(conn->server_sock);
	conn->server_sock=conn->client_sock=0;
	conn->stat=cs_disconnected;
	return -1;
    }
    fcntl(conn->client_sock, F_SETFL, O_NONBLOCK);
    conn->stat=cs_connecting;
    return 0;
}

void conn_close_client(Conn *conn)
{
    debug("conn_close_client(): s=%d", conn->client_sock);
    shutdown(conn->client_sock, 2);
    close(conn->client_sock);
    conn->client_sock=-1;
    if (conn->server_sock==-1) conn->stat=cs_disconnected;
}

void conn_close_server(Conn *conn)
{
    debug("conn_close_server(): s=%d", conn->server_sock);
    if (log_flag) plog(LOG_INFO, "DISCONNECT @%d", conn->server_sock);
    SSL_free(conn->ssl_conn);
    shutdown(conn->server_sock, 2);
    close(conn->server_sock);
    conn->server_sock=-1;
    if (conn->client_sock==-1) conn->stat=cs_disconnected;
}

void sighandler(int signum)
{
    switch (signum) {
	case SIGINT:
	case SIGTERM:
	    plog(LOG_NOTICE, "SIGNAL Interrupt/terminate");
	    server_done();
	    // If it's possible to remove pid file, try it..
	    // It's not guaranteed to succeed, because of setuid
	    if (!chroot_dir) unlink("/var/run/ssl_proxy.pid");
	    exit(0);
	default:;
    }
}

int main(int argc, char **argv)
{
    FILE *pidfile;
    int c, pid, i;
    char *p1, *p2;

    while ((c=getopt(argc, argv, "hdfilm:s:c:C:K:p:u:r:v:V:t:U:D:")) != EOF)
	switch (c) {
	    case 'h':
		fprintf(stderr, "Symbion SSL proxy " VERSION "\n"
			"usage: %.256s [-d] [-f] [-l] [-i] [-s <listen address>] [-c <client address>]\n"
			"              [-m <max connection>] [-C <certificate file>] [-K <key file>]\n"
			"              [-p <cipher list>] [-u <user/uid>] [-r <chroot dir>]\n"
			"              [-v <trusted CA file>] [-V <trusted CA dir>]\n"
			"              [-t <timeout (sec)>]\n"
			"              [-U <upward buffer (default 2048)>] [-D <downward buffer (default 8192)>]\n"
			"        <lister address> = [<host>:]<port>\n"
			"        <client address> = [<host>:]<port> | unix:<path>\n", argv[0]);
		fprintf(stderr, "       %.256s -h\n", argv[0]);
		exit(0);
	    case 'd':
		debug_flag=1;
		break;
	    case 'f':
		fg_flag=1;
		break;
	    case 'i':
		info_flag=1;
		break;
	    case 'l':
		log_flag=1;
		break;
	    case 'm':
		max_conn=atoi(optarg);
		break;
	    case 's':
		server_port=atoi(optarg);
		p1=strtok(optarg, ":");
		p2=strtok(NULL, "");
		if (p2) {
		    server_addr=p1;
		    server_port=atoi(p2);
		} else {
		    server_addr="0.0.0.0"; server_port=atoi(p1);
		}
		break;
	    case 'c':
		p1=strtok(optarg, ":");
		p2=strtok(NULL, "");
		if (p2) {
		    if (!strcmp(p1, "unix")) {
			client_s_family=AF_UNIX;
			client_addr=p2;
			client_port=0;
		    } else {
			client_addr=p1;
			client_port=atoi(p2);
		    }
		} else {
		    client_addr="localhost"; client_port=atoi(p1);
		}
		break;
	    case 'C':
		cert_file=optarg;
		break;
	    case 'K':
		key_file=optarg;
		break;
	    case 'p':
		cipher_list=optarg;
		break;
	    case 'u':
		set_uid=optarg;
		break;
	    case 'r':
		chroot_dir=optarg;
		break;
	    case 'v':
		verify_ca_file=optarg;
		break;
	    case 'V':
		verify_ca_dir=optarg;
		break;
	    case 't':
		conn_timeout=atoi(optarg);
		break;
	    case 'U':
		cs_buflen=atoi(optarg);
		break;
	    case 'D':
		sc_buflen=atoi(optarg);
		break;
	}
    debug("Symbion SSL proxy " VERSION);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);
    // This must be done before process_security_init(), because server_port
    // can be a privileged port, ssl_init use files from the filesystem.
    if (client_s_family==AF_INET)
	debug("Using server: family=INET host=%.256s port=%d", client_addr, client_port);
    else
	debug("Using server: family=UNIX path=%.256s", client_addr);
    server_init(server_addr, server_port, max_conn);
    server_ssl_init();
    client_init(client_addr, client_port);
    if (!debug_flag && !fg_flag && (pid=fork())) {
	pidfile=fopen("/var/run/ssl_proxy.pid", "w");
	if (pidfile) {
	    fprintf(pidfile, "%d\n", pid);
	    fclose(pidfile);
	}
	exit(0);
    }

    // Process security
    if (set_uid) {
	if (!(pass=getpwnam(set_uid))) {perror("getpwnam()"); exit(1);}
    }
    if (chroot_dir) {
	debug("Changing root directory to '%.256s'..", chroot_dir);
	if (chroot(chroot_dir)<0) {perror("chroot()"); exit(1);}
	chdir("/");
    }
    if (set_uid) {
	debug("Changing userID to %.256s..", set_uid);
	setgid(pass->pw_gid);
	setuid(pass->pw_uid);
    }

    conn=malloc(max_conn*sizeof(Conn));
    bzero(conn, max_conn*sizeof(Conn));
    for (i=0; i<max_conn; i++) {
	Conn *c=&conn[i];
	c->scbuf=malloc(sc_buflen);
	c->scbuf_b=c->scbuf; c->scbuf_e=c->scbuf;
	c->csbuf=malloc(cs_buflen);
	c->csbuf_b=c->csbuf; c->csbuf_e=c->csbuf;
    }

    openlog("sslproxy", LOG_PID, LOG_DAEMON);
    if (client_s_family==AF_INET)
	plog(LOG_NOTICE, "INIT Version " VERSION " started (family=INET host=%.256s port=%d).",
		client_addr, client_port);
    else
	plog(LOG_NOTICE, "INIT Version " VERSION " started (family=UNIX path=%.256s).",
		client_addr);

    while (1) {
	int eventsum=0, ci;
	// Check for incoming connections
	if ((i=conn_accept())>0) {
	    debug("Client connected");
	    eventsum=1;
	}
	for (ci=0; ci<max_conn; ci++) {
	    Conn *cn=&conn[ci];
	    int event=0, l;
	    time_t tm;
	    switch (cn->stat) {
		case cs_accept:
		    i=conn_ssl_accept(cn);
//		    cn->c_end_req=0; cn->s_end_req=0;
		    event|=(i==0);
		    break;
		case cs_connecting:
		    if (connect(cn->client_sock, client_sa, client_sa_len)<0) {
			if (errno==EINPROGRESS) break;
//			if (errno==EALREADY) break;
			plog(LOG_ERR, "ERROR @%d connect(): %s", conn->server_sock, strerror(errno));
			close(cn->client_sock);
			SSL_free(cn->ssl_conn);
			close(cn->server_sock);
			cn->stat=cs_disconnected;
		    } else {
			struct sockaddr_in client_addr;
			unsigned int client_addr_len=sizeof(client_addr);
			X509 *cert;
			X509_NAME *xn=NULL;
			char peer_cn[256]="";
			getpeername(cn->server_sock,
				(struct sockaddr *)&client_addr,
				&client_addr_len);
			cert=SSL_get_peer_certificate(cn->ssl_conn);
			if (cert) {
			    xn=X509_get_subject_name(cert);
			    X509_NAME_get_text_by_NID(xn, NID_commonName, peer_cn, 256);
			}
			if (info_flag) {
			    cn->csbuf_e+=snprintf(cn->csbuf_b, cs_buflen,
				    "#@ip=%s port=%d%s%s%s\r\n",
				    inet_ntoa(client_addr.sin_addr),
				    htons(client_addr.sin_port), xn?" cn='":"", peer_cn, xn?"'":"");
			    debug("INFO: %p %d %s", cn, cn->server_sock, cn->csbuf);
			}
			if (log_flag) plog(LOG_INFO, "CONNECT @%d %s:%d%s%s%s",
				cn->server_sock, inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port),
				xn?" cn='":"", peer_cn, xn?"'":"");
			cn->stat=cs_connected;
		    }
		    break;
		case cs_connected:
		    // Check if data is available on client side
		    if ((l=cs_buflen-(cn->csbuf_e-cn->csbuf))) {
			i=SSL_read(cn->ssl_conn, cn->csbuf_e, l);
			if (i<=0) { // Error, or shutdown
			    if (errno!=EAGAIN) {
				plog_ssl_error(cn->ssl_conn, i, "SSL_read()",
					conn->server_sock);
				cn->stat=cs_closing; event=1;
//				cn->c_end_req=1;
			    }
			} else cn->csbuf_e+=i;
		    }
		case cs_closing:
		    // Send buffered data to server
		    if ((l=cn->csbuf_e-cn->csbuf_b)>0) {
			i=write(cn->client_sock, cn->csbuf_b, l); event=1;
			if (debug_flag) write(2, cn->csbuf_b, l);
			if (i>=0) {
			    cn->csbuf_b+=i;
			} else {
			    if (errno!=EAGAIN) {
				plog(LOG_ERR, "ERROR @%d write(): %s",
					conn->server_sock, strerror(errno));
				cn->csbuf_b=cn->csbuf_e=cn->csbuf;
				cn->stat=cs_closing;
			    }
			}
			if (cn->csbuf_b==cn->csbuf_e) {
			    cn->csbuf_b=cn->csbuf_e=cn->csbuf;
//			    if (cn->c_end_req) conn_close(cn);
			}
		    }
		    if (cn->stat==cs_closing && cn->csbuf_e==cn->csbuf_b) conn_close_client(cn);
		default:;
	    }
	    if (cn->stat==cs_connected || cn->stat==cs_closing) {
		// Check if data is available on server side
		if ((l=sc_buflen-(cn->scbuf_e-cn->scbuf)) && cn->client_sock>=0) {
		    i=read(cn->client_sock, cn->scbuf_e, l);
		    if (!i) { // End of connection
			cn->stat=cs_closing; event=1;
//			cn->s_end_req=1;
		    } else if (i<0) { // Error
			if (errno!=EAGAIN) {
			    plog(LOG_ERR, "ERROR @%d read(): %s",
				    conn->server_sock, strerror(errno));
			    cn->stat=cs_closing; event=1;
//			    cn->s_end_req=1;
			}
		    } else cn->scbuf_e+=i;
		}
		// Send buffered data to client
		if ((l=cn->scbuf_e-cn->scbuf_b)>0 && cn->server_sock>=0) {
		    i=SSL_write(cn->ssl_conn, cn->scbuf_b, l);
		    if (i>0) debug("transfer: buf=%d, b=%d, l=%d, i=%d", cn->scbuf,
			    cn->scbuf_b, l, i);
		    if (i>=0) {
			cn->scbuf_b+=i; event=1;
		    } else if (errno!=EAGAIN) {
			plog_ssl_error(cn->ssl_conn, i, "SSL_write()",
				conn->server_sock);
			cn->scbuf_b=cn->scbuf_e=cn->scbuf;
			event=1;
		    }
		    if (cn->scbuf_b==cn->scbuf_e) {
			cn->scbuf_b=cn->scbuf_e=cn->scbuf;
//			if (cn->s_end_req) conn_close(cn);
		    }
		}
		if (cn->stat==cs_closing && cn->scbuf_e==cn->scbuf_b) conn_close_server(cn);
		tm=time(NULL);
		if (event) {
		    cn->event_t=tm;
		}
		if (conn_timeout && cn->stat!=cs_disconnected && tm-cn->event_t>conn_timeout) {
		    cn->stat=cs_closing; event=1;
		    plog(LOG_ERR, "TIMEOUT @%d", conn->server_sock);
		}
	    }
	    eventsum+=event;
	}
	if (!eventsum) _sleep();
    }
    return 0;
}
