export SSLPROXY_DIR = $(shell pwd)
include Makefile.global

TARGET = ssl_proxy
OBJS = ssl_proxy.o

all: $(TARGET)

clean:
	rm -f $(TARGET) core *.o

release: r_tgz

r_tgz:
	git-archive --format=tar --prefix=sslproxy-$(VERSION)/ HEAD |gzip -9 >sslproxy-$(VERSION).tar.gz

$(TARGET): $(OBJS)
	$(LD) -o $@ $(OBJS) $(LDOPTS)

%.o: %.c
	$(CC) -c $(COPTS) $< -o $@
