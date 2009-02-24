export SSLPROXY_DIR = $(shell pwd)
include Makefile.global

TARGET = ssl_proxy
OBJS = ssl_proxy.o

all: $(TARGET)

clean:
	rm -f $(TARGET) core *.o

release: r_tag r_tgz

$(TARGET): $(OBJS)
	$(LD) -o $@ $(OBJS) $(LDOPTS)

%.o: %.c
	$(CC) -c $(COPTS) $< -o $@
