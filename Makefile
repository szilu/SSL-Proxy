export SSLPROXY_DIR = $(shell pwd)
include Makefile.global

TARGET = ssl_proxy
OBJS = ssl_proxy.o

all: $(TARGET)

clean:
	rm -f $(TARGET) core *.o

r_tag:
	cvs tag -c -R rel-$(MAJOR_VERSION)_$(MINOR_VERSION)_$(MICRO_VERSION)

r_tgz:
	cvs -d :ext:szilu@cvs.sourceforge.net:/cvsroot/sslproxy export -r rel-$(MAJOR_VERSION)_$(MINOR_VERSION)_$(MICRO_VERSION) -d ssl_proxy-$(VERSION) sslproxy
	tar cvzf ../ssl_proxy-$(VERSION).tgz ssl_proxy-$(VERSION)
	rm -rf ssl_proxy-$(VERSION)

release: r_tag r_tgz

$(TARGET): $(OBJS)
	$(LD) -o $@ $(OBJS) $(LDOPTS)

%.o: %.c
	$(CC) -c $(COPTS) $< -o $@
