PROGRAMS= host_scan spoofer
CC=gcc
#CFLAGS?=-Wall -ggdb
CFLAGS?=-O2
LDFLAGS+=-lpcap -lssl -lcrypto -I..
PREFIX=/usr/local
LIBS=../thc-ipv6-lib.o

all: $(PROGRAMS)

%:	%.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f $(PROGRAMS) *~ core DEADJOE

strip:	all
	strip $(PROGRAMS)

install:	strip
	install -m0755 -d ${DESTDIR}${PREFIX}/bin
	install -m0755 $(PROGRAMS) ${DESTDIR}${PREFIX}/bin

.PHONY: all install clean
