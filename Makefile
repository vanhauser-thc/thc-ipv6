# Comment out if openssl-dev is not present
# of if you want to compile statc
HAVE_SSL=yes

# comment in if you want to compile static tools
#STATIC=-static

#CC=gcc
#CFLAGS=-g
CFLAGS+=-g -O3 -march=native -flto -falign-functions -falign-jumps -falign-loops -falign-labels -freorder-blocks
CFLAGS+=$(if $(HAVE_SSL),-D_HAVE_SSL,)
LDFLAGS+=-lpcap $(if $(HAVE_SSL),-lssl -lcrypto,)
PROGRAMS=parasite6 dos-new-ip6 detect-new-ip6 fake_router6 fake_advertise6 fake_solicitate6 fake_mld6 fake_mld26 fake_mldrouter6 flood_mldrouter6 fake_mipv6 redir6 smurf6 alive6 toobig6 rsmurf6 implementation6 implementation6d sendpees6 sendpeesmp6 randicmp6 fuzz_ip6 flood_mld6 flood_mld26 flood_router6 flood_advertise6 flood_solicitate6 trace6 exploit6 denial6 fake_dhcps6 flood_dhcpc6 fake_dns6d fragmentation6 kill_router6 fake_dnsupdate6 ndpexhaust6 detect_sniffer6 dump_router6 fake_router26 flood_router26 passive_discovery6 dnsrevenum6 inverse_lookup6 node_query6 address6 covert_send6 covert_send6d inject_alive6 firewall6 ndpexhaust26 fake_pim6 thcsyn6 redirsniff6 flood_redir6 four2six dump_dhcp6 flood_rs6 fuzz_dhcps6 fuzz_dhcpc6 toobigsniff6 flood_unreach6 connect6
EXTRA=dnssecwalk dnsdict6 thcping6 fragrouter6 connsplit6
LIBS=thc-ipv6-lib.o
STRIP=strip

PREFIX=/usr/local
MANPREFIX=${PREFIX}/share/man
MANPAGES=$(foreach p, $(PROGRAMS) $(EXTRA), $(p).8)

all:	$(LIBS) $(PROGRAMS) $(EXTRA) $(MANPAGES)

dnssecwalk:	dnssecwalk.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(STATIC) -o $@ $^ $(LDFLAGS)

dnsdict6:	dnsdict6.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(STATIC) -o $@ $^ $(LDFLAGS) -lpthread -lresolv

thcping6:	thcping6.c $(LIBS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(STATIC) -o $@ $^ $(LDFLAGS) -lrt

fragrouter6:	fragrouter6.c $(LIBS)
	-$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) -lnetfilter_queue || /bin/echo -e "\nCompilation of fragrouter6 failed, you have to install libnetfilter-queue-dev for this!\n"

connsplit6:	connsplit6.c $(LIBS)
	-$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) -lnetfilter_queue || /bin/echo -e "\nCompilation of connsplit6 failed, you have to install libnetfilter-queue-dev for this!\n"

%:	%.c $(LIBS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(STATIC) -o $@ $^ $(LDFLAGS)

strip:	all
	-$(STRIP) $(PROGRAMS) $(EXTRA)

install: all strip
	install -m0755 -d ${DESTDIR}${PREFIX}/bin
	-install -m0755 $(PROGRAMS) $(EXTRA) grep6.pl *.sh ${DESTDIR}${PREFIX}/bin
	install -m0755 -d ${DESTDIR}${MANPREFIX}/man8
	install -m0644 -D thc-ipv6.8 ${DESTDIR}${MANPREFIX}/man8
	install -m0644 -D $(MANPAGES) ${DESTDIR}${MANPREFIX}/man8

clean:
	rm -f $(PROGRAMS) $(EXTRA) $(LIBS) core DEADJOE *~
	rm -f $(MANPAGES)

backup:	clean
	tar czvf ../thc-ipv6-bak.tar.gz *
	sync

%.8: %
	@echo .TH $* 8 `date -I` THC "IPv6 ATTACK TOOLKIT" > $@
	@echo .SH NAME >> $@
	@echo .B $* >> $@
	@./$*|tail -n +2|sed -e "s#\\./$*#$*#g" -e "s/^Syntax: \?/.SH SYNOPSIS\n/g" -e "s/Options:/.SH OPTIONS\n.nf\n/g" -e "s/^\(.*\):\$$/.SH \1\n/g" >> $@
	@echo .SH AUTHOR >> $@
	@echo "thc-ipv6 was written by van Hauser <vh@thc.org> / THC" >> $@
	@echo >> $@
	@echo  The homepage for this toolkit is: https://github.com/vanhauser-thc/thc-ipv6 >> $@
	@echo >> $@
	@echo .SH COPYRIGHT >> $@
	@./$* |head -n1|sed -e "s#^\./##g" >> $@

.PHONY: all install clean man
