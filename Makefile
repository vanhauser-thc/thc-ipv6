# Comment out if openssl-dev is not present
HAVE_SSL=yes

CC=gcc
#CFLAGS=-g
CFLAGS=-O2
CFLAGS+=$(if $(HAVE_SSL),-D_HAVE_SSL,)
LDFLAGS+=-lpcap $(if $(HAVE_SSL),-lssl -lcrypto,)
PROGRAMS=parasite6 dos-new-ip6 detect-new-ip6 fake_router6 fake_advertise6 fake_solicitate6 fake_mld6 fake_mld26 fake_mldrouter6 flood_mldrouter6 fake_mipv6 redir6 smurf6 alive6 toobig6 rsmurf6 implementation6 implementation6d sendpees6 sendpeesmp6 randicmp6 fuzz_ip6 flood_mld6 flood_mld26 flood_router6 flood_advertise6 flood_solicitate6 trace6 exploit6 denial6 fake_dhcps6 flood_dhcpc6 fake_dns6d fragmentation6 kill_router6 fake_dnsupdate6 ndpexhaust6 detect_sniffer6 dump_router6 fake_router26 flood_router26 passive_discovery6 dnsrevenum6 inverse_lookup6 node_query6 address6 covert_send6 covert_send6d inject_alive6 firewall6 ndpexhaust26 fake_pim6 thcsyn6 redirsniff6 flood_redir6 four2six dump_dhcp6 fuzz_dhcps6 flood_rs6 fuzz_dhcpc6
LIBS=thc-ipv6-lib.o
STRIP=echo

PREFIX=/usr/local
MANPREFIX=${PREFIX}/share/man

all:	$(LIBS) $(PROGRAMS) dnssecwalk dnsdict6 thcping6

dnssecwalk:	dnssecwalk.c
	$(CC) $(CFLAGS) -o $@ $^

dnsdict6:	dnsdict6.c
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lresolv

thcping6:	thcping6.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lrt

%:	%.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

strip:	all
	$(STRIP) $(PROGRAMS) dnssecwalk dnsdict6 thcping6

install: all strip
	install -m0755 -d ${DESTDIR}${PREFIX}/bin
	install -m0755 $(PROGRAMS) dnsdict6 thcping6 dnssecwalk *.sh ${DESTDIR}${PREFIX}/bin
	install -m0755 -d ${DESTDIR}${MANPREFIX}/man8
	install -m0644 -D thc-ipv6.8 ${DESTDIR}${MANPREFIX}/man8

clean:
	rm -f $(PROGRAMS) dnsdict6 thcping6 dnssecwalk $(LIBS) core DEADJOE *~

backup:	clean
	tar czvf ../thc-ipv6-bak.tar.gz *
	sync

.PHONY: all install clean 
