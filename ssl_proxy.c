/* Symbion SSL Proxy V0.9.1
 * Copyright (C) 2000 Szilard Hajba
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define VERSION "0.9.1"
#define BUFLEN 8192
#define MAX_CONNECTION 32
#define CS_BUFFER_LEN 2048
#define SC_BUFFER_LEN 8192
#define PEM_DIR "/etc/symbion"
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

int debug_flag=0;
int max_conn=MAX_CONNECTION;
int cs_buflen=CS_BUFFER_LEN, sc_buflen=SC_BUFFER_LEN;
int server_port=443;
char *client_host="localhost";
int client_port=80;
char *cert_file=PEM_DIR"/"CERT_FILE, *key_file=PEM_DIR"/"KEY_FILE;
char *chroot_dir=NULL, *set_uid=NULL;
struct passwd *pass;

int server_socket;
SSL_CTX *server_ssl_ctx;
X509 *ssl_public_cert;
RSA *ssl_private_key;

struct sockaddr_in client_sa;
typedef enum {cs_disconnected, cs_accept, cs_connected} ConnStatus;
typedef struct {
    ConnStatus stat;			// Status of the connection
    int server_sock;			// Server side socket id
    struct sockaddr_in server_sa;	// Server's socket address
    int server_sa_len;			// ^^^^^^^^^^^^^^^^^^^^^^^'s len
    SSL *ssl_conn;			// SSL connection structure pointer
    int client_sock;			// Client side socket id
    char *csbuf;			// Server side write buffer
    char *csbuf_b;			// Server side write buffer begin ptr
    char *csbuf_e;			// Server side write buffer end ptr
    int c_end_req;			// Client requested connection close
    char *scbuf;			// Client side write buffer
    char *scbuf_b;			// Client side write buffer begin ptr
    char *scbuf_e;			// Client side write buffer end ptr
    int s_end_req;			// Server requested connection close
} Conn;
Conn *conn=NULL;

void conn_close(Conn *conn);

void log(const char *cls, const char *format,...) {
    char str[8192];
    va_list args;
    va_start(args, format);
    vsprintf(str, format, args);
    va_end(args);
    fprintf(stderr, "%.256s: %.256s\n", cls, str);
}

void debug(char *format,...) {
    char str[8192];
    if (debug_flag) {
	va_list args;
	va_start(args, format);
	vsprintf(str, format, args);
	va_end(args);
	fprintf(stderr, "%.256s\n", str);
    }
}

// ============================================== Server
int server_init(int port, int maxconn) {
    struct sockaddr_in server;

    server_socket=socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket<0) {
	perror("socket()");
	exit(1);
    }
    server.sin_family=AF_INET;
    server.sin_addr.s_addr=htons(INADDR_ANY);
    server.sin_port=htons(port);
    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
	perror("bind()");
	exit(1);
    }
    listen(server_socket, maxconn);
    fcntl(server_socket, F_SETFL, O_NONBLOCK);
    return server_socket;
}

void server_done() {
    int ci;
    shutdown(server_socket, 2);
    usleep(100);
    close(server_socket);
    for (ci=0; ci<max_conn; ci++)
	if (conn[ci].stat==cs_accept && conn[ci].stat==cs_connected)
	    conn_close(&conn[ci]);
}

// ============================================== Server SSL
static RSA *tmp_rsa_cb(SSL *ssl, int export, int key_len) {
    static RSA *rsa=NULL; 
    debug("Generating new RSA key.. (ex=%d, kl=%d)", export, key_len);
    if (export) {
	rsa=RSA_generate_key(key_len, RSA_F4, NULL, NULL);
    } else {
	log("tmp_rsa_callback()", "Export not set");
    }
    return rsa;
}

void server_ssl_init(char *cert, char *key) {
    FILE *f;
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    server_ssl_ctx=SSL_CTX_new(SSLv23_server_method());
    if (!SSL_CTX_set_default_verify_paths(server_ssl_ctx))  {
	fprintf(stderr, "cannot set default path\n");
	exit(1);
    }

    // Load certificate file
    f=fopen(cert_file, "r");
    if (!f)  {
	fprintf(stderr,"cannot open public cert file \"%.256s\"\n",cert_file);
	exit(1);
    }
    ssl_public_cert=X509_new();
    if (!PEM_read_X509(f, &ssl_public_cert, NULL, NULL))  {
	fprintf(stderr,"error reading public cert: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    fclose(f);

    // Load key file
    f=fopen(key_file, "r");
    if (!f)  {
	fprintf(stderr,"cannot open private key file \"%.256s\"\n",key_file);
	exit(1);
    }
    ssl_private_key=RSA_new();
    if (!PEM_read_RSAPrivateKey(f, &ssl_private_key, NULL, NULL))  {
	fprintf(stderr,"error reading private key: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    fclose(f);
    SSL_CTX_set_tmp_rsa_callback(server_ssl_ctx, tmp_rsa_cb);
//    SSL_CTX_set_session_cache_mode(server_ssl_ctx, SSL_SESS_CACHE_OFF);
}

// ============================================== CLient
void client_init(char *host, int port) {
    struct hostent *hp;
    client_sa.sin_family=AF_INET;
    hp=gethostbyname(host);
    if (hp==NULL) {
        perror("bind()");
        exit(1);
    }
    bcopy(hp->h_addr, &client_sa.sin_addr, hp->h_length);
    client_sa.sin_port=htons(port);
}

// ============================================== Connection
struct sockaddr_in server_sa;
unsigned int server_sa_len;
int conn_accept() {
    int i;
    // Initialize SSL connection (server side)
    int s=accept(server_socket, &server_sa, &server_sa_len);
    // FIXME
//    if (server_sa_len>32) server_sa_len=0;
    if (s<=0) return 0;
    debug("conn_accept(): Client connected");
    for (i=0; i<max_conn && conn[i].stat!=cs_disconnected; i++);
    if (i==max_conn) {
	log("accept", "Internal error");
	close(s);
	return 0;
    }
    debug("accept(): sn=%d sock=%d", i, s);
    conn[i].server_sock=s;
    bcopy(&server_sa, &conn[i].server_sa, server_sa_len);
    conn[i].server_sa_len=server_sa_len;
//    fcntl(conn[i].server_sock, F_SETFL, O_NONBLOCK);
    conn[i].ssl_conn=SSL_new(server_ssl_ctx);
    SSL_set_fd(conn[i].ssl_conn, conn[i].server_sock);
    if (!SSL_use_RSAPrivateKey(conn[i].ssl_conn, ssl_private_key)) {
	log("accept", "Error reading private key");
	SSL_free(conn[i].ssl_conn);
	close(conn[i].server_sock);
	return -1;
    }
    if (!SSL_use_certificate(conn[i].ssl_conn, ssl_public_cert)) {
	log("accept", "Error reading public certificate");
	SSL_free(conn[i].ssl_conn);
	close(conn[i].server_sock);
	return -1;
    }
    SSL_set_verify(conn[i].ssl_conn, 0, NULL);
    BIO_set_nbio(SSL_get_rbio(conn[i].ssl_conn), 0);
    BIO_set_nbio(SSL_get_wbio(conn[i].ssl_conn), 0);
    fcntl(conn[i].server_sock, F_SETFL, O_NONBLOCK);
    conn[i].stat=cs_accept;
    return conn[i].server_sock;
}

int conn_ssl_accept(Conn *conn) {
    int ret=SSL_accept(conn->ssl_conn);
    // What's the return value of SSL_accept? :)
    // I couldn't find it in any documentation I have. Empirical tests made me
    // think -1 means error, 1 means succesful connect and 0 means succesful
    // disconnect.
//    debug("SSL_accept: %d, SSL_want=%d", ret, SSL_want(conn->ssl_conn));
    if (ret<=0) {
	unsigned long err;
	if ((err=ERR_get_error())) {
	    log("accept", "Access failed: %.256s", ERR_error_string(err, NULL));
	} else if (SSL_want(conn->ssl_conn)>1) return 0;;
	debug("SSL_accept: disconnected.");
	SSL_free(conn->ssl_conn);
	close(conn->server_sock);
	conn->stat=cs_disconnected;
	return -1;
    }

    // Connect to server (client side)
    conn->client_sock=socket(AF_INET, SOCK_STREAM, 0);
    if (conn->client_sock<0) {
	log("socket()", sys_errlist[errno]);
	SSL_free(conn->ssl_conn);
	close(conn->server_sock);
	conn->stat=cs_disconnected;
	return -1;
    }
    if (connect(conn->client_sock, (struct sockaddr *)&client_sa, sizeof(struct sockaddr_in))<0) {
	log("connect()", sys_errlist[errno]);
	close(conn->client_sock);
	SSL_free(conn->ssl_conn);
	close(conn->server_sock);
	conn->stat=cs_disconnected;
	return -1;
    }
    fcntl(conn->client_sock, F_SETFL, O_NONBLOCK);
    conn->stat=cs_connected;
    return 0;
}

void conn_close(Conn *conn) {
    debug("conn_close(): Closing connection (s=%d)", conn->server_sock);
    shutdown(conn->client_sock, 2);
    close(conn->client_sock);
    SSL_free(conn->ssl_conn);
    shutdown(conn->server_sock, 2);
    close(conn->server_sock);
    conn->stat=cs_disconnected;
}

void sighandler(int signum) {
    switch (signum) {
	case SIGINT:
	case SIGTERM:
	    log("SIGNAL", "Interrupt/terminate");
	    server_done();
	    // If it's possible to remove pid file, try it..
	    // It's not guaranteed to succeed, because of setreuid
	    if (!chroot_dir) unlink("/var/run/ssl_proxy.pid");
	    exit(0);
	default:
    }
}

int main(int argc, char **argv) {
    FILE *pidfile;
    int c, pid, i;
    char *p1, *p2;

    debug("Symbion SSL proxy V" VERSION "\n");
    while ((c=getopt(argc, argv, "hdm:s:c:C:K:u:r:")) != EOF)
	switch (c) {
	    case 'h':
		fprintf(stderr, "usage: %.256s [-d] [-s <server port>] [-c [<client host>:]<client port>]\n", argv[0]);
		fprintf(stderr, "               [-m <max connection>] [-C <certificate file>] [-K <key file>]\n");
		fprintf(stderr, "               [-u <user/uid>] [-r <chroot dir>]\n");
		fprintf(stderr, "       %.256s -h\n", argv[0]);
		exit(0);
	    case 'd':
		debug_flag=1;
		break;
	    case 'm':
		max_conn=atoi(optarg);
		break;
	    case 's':
		server_port=atoi(optarg);
		break;
	    case 'c':
		p1=strtok(optarg, ":");
		p2=strtok(NULL, "");
		if (p2) {
		    client_host=p1; client_port=atoi(p2);
		} else {
		    client_host="localhost"; client_port=atoi(p1);
		}
		break;
	    case 'C':
		cert_file=optarg;
		break;
	    case 'K':
		key_file=optarg;
		break;
	    case 'u':
		set_uid=optarg;
		break;
	    case 'r':
		chroot_dir=optarg;
		break;
	}
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    // This must be done before process_security_init(), because server_port
    // can be a privileged port, ssl_init use files from the filesystem.
    debug("Using server: %.256s, port: %d", client_host, client_port);
    server_init(server_port, max_conn);
    server_ssl_init(cert_file, key_file);
    client_init(client_host, client_port);
    if (!debug_flag && (pid=fork())) {
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
	debug("Changing real and effective userID to %.256s..", set_uid);
	setreuid(pass->pw_uid, pass->pw_uid);
	setregid(pass->pw_gid, pass->pw_gid);
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

    while (1) {
	int event=0, ci;
	// Check for incoming connections
	if ((i=conn_accept())>0) {
	    debug("Client connected");
	    event=1;
	}
	for (ci=0; ci<max_conn; ci++) {
	    Conn *cn=&conn[ci];
	    switch (cn->stat) {
		case cs_accept:
		    i=conn_ssl_accept(cn);
		    cn->c_end_req=0; cn->s_end_req=0; event=1;
		    break;
		case cs_connected:
		    // Check if data is available on server side
		    i=SSL_read(cn->ssl_conn, cn->csbuf_e, cs_buflen-(cn->csbuf_e-cn->csbuf));
		    if (!i) { // End of connection
			debug("Close request: %d", ci);
			cn->c_end_req=1; event=1;
		    } else if (i<0) { // Error
			if (errno!=EAGAIN) {
			    debug("SSL_read() errno: %d", errno);
			    cn->c_end_req=1; event=1;
			}
		    } else cn->csbuf_e+=i;
		    if (cn->csbuf_e-cn->csbuf_b>0) {
			i=write(cn->client_sock, cn->csbuf_b, cn->csbuf_e-cn->csbuf_b); event=1;
			if (debug_flag) write(2, cn->csbuf_b, cn->csbuf_e-cn->csbuf_b);
			if (i>0) cn->csbuf_b+=i;
			if (cn->scbuf_b==cn->scbuf_e) {
			    cn->scbuf_b=cn->scbuf_e=cn->scbuf;
			    if (cn->c_end_req) conn_close(cn);
			}
		    }
		default:
	    }
	    if (cn->stat==cs_connected) {
		// Check if data is available on client side
		if (sc_buflen-(cn->scbuf_e-cn->scbuf)) {
		    i=read(cn->client_sock, cn->scbuf_e, sc_buflen-(cn->scbuf_e-cn->scbuf));
		    if (!i) { // End of connection
			cn->s_end_req=1; event=1;
		    } else if (i<0) { // Error
			if (errno!=EAGAIN) {
			    debug("read errno: %d", errno);
			    cn->s_end_req=1; event=1;
			}
		    } else cn->scbuf_e+=i;
		}
		if (cn->scbuf_e-cn->scbuf_b>0) {
		    i=SSL_write(cn->ssl_conn, cn->scbuf_b, cn->scbuf_e-cn->scbuf_b);
		    if (i>0) debug("transfer: buf=%d, b=%d, l=%d, i=%d", cn->scbuf,
			    cn->scbuf_b, cn->scbuf_e-cn->scbuf_b, i);
		    if (i>=0) {
			cn->scbuf_b+=i; event=1;
		    }
		    else if (errno!=EAGAIN) {
			debug("SSL_write() errno: %d", errno);
			event=1;
		    }
		    if (cn->scbuf_b==cn->scbuf_e) {
			cn->scbuf_b=cn->scbuf_e=cn->scbuf;
			if (cn->s_end_req) conn_close(cn);
		    }
		}
	    }
	}
	if (!event) usleep(100);
    }
    return 0;
}
