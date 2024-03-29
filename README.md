                  
                      THC-IPV6-ATTACK-TOOLKIT
  (c) 2005-2022 vh@thc.org https://github.com/vanhauser-thc/thc-ipv6


		Licensed under AGPLv3 (see LICENSE file)


INTRODUCTION
============
This code was inspired when I got into touch with IPv6, learned more and
more about it - and then found no tools to play (read: "hack") around with.
First I tried to implement things with libnet, but then found out that
the IPv6 implementation is only partial - and sucks. I tried to add the
missing code, but well, it was not so easy, hence I saved my time and
quickly wrote my own library.


LIMITATIONS
===========
This code currently only runs on:
 - Linux 2.6.x or newer (because of /proc usage)
 - Ethernet
But this means for all linux guys that it will work for 98% of your use cases.
Patches are welcome! (add "antispam" in the subject line to get through my
anti-spam protection, otherwise the email will bounce)


BUILDING
========
You must have libpcap-dev installed to be able to build the tools.
Additionally libssl-dev and libnetfilter-queue-dev are recommended as well.

These can be installed by (Kali, Debian, Ubuntu):
  sudo apt-get install libpcap-dev libssl-dev libnetfilter-queue-dev

You can build the tools by running:
   make all

You can install the tools and existing manual pages by running:
   make install


THE TOOLS
=========
The THC IPV6 ATTACK TOOLKIT comes already with lots of effective attacking
tools:
 - parasite6: ICMPv6 neighbor solitication/advertisement spoofer, puts you
   as man-in-the-middle, same as ARP mitm (and parasite)
 - alive6: an effective alive scanng, which will detect all systems
   listening to this address
 - dnsdict6: parallized DNS IPv6 dictionary bruteforcer
 - fake_router6: announce yourself as a router on the network, with the
   highest priority
 - redir6: redirect traffic to you intelligently (man-in-the-middle) with
   a clever ICMPv6 redirect spoofer
 - toobig6: mtu decreaser with the same intelligence as redir6
 - detect-new-ip6: detect new IPv6 devices which join the network, you can
   run a script to automatically scan these systems etc.
 - dos-new-ip6: detect new IPv6 devices and tell them that their chosen IP
   collides on the network (DOS).
 - trace6: very fast traceroute6 with supports ICMP6 echo request and TCP-SYN
 - flood_router6: flood a target with random router advertisements
 - flood_advertise6: flood a target with random neighbor advertisements
 - fuzz_ip6: fuzzer for IPv6 
 - implementation6: performs various implementation checks on IPv6 
 - implementation6d: listen daemon for implementation6 to check behind a FW
 - fake_mld6: announce yourself in a multicast group of your choice on the net
 - fake_mld26: same but for MLDv2
 - fake_mldrouter6: fake MLD router messages
 - fake_mipv6: steal a mobile IP to yours if IPSEC is not needed for authentication
 - fake_advertiser6: announce yourself on the network
 - smurf6: local smurfer
 - rsmurf6: remote smurfer, known to work only against linux at the moment
 - exploit6: known IPv6 vulnerabilities to test against a target
 - denial6: a collection of denial-of-service tests againsts a target
 - thcping6: sends a hand crafted ping6 packet
 - sendpees6: a tool by willdamn@gmail.com, which generates a neighbor
   solicitation requests with a lot of CGAs (crypto stuff ;-) to keep the
   CPU busy. nice.
and about 25 more tools for you to discover :-)

Just run the tools without options and they will give you help and show the
command line options.



THE LIBRARY
===========
The library thc-ipv6-lib.c is the heart and soul of all tools - and those
you may want to write.
Implementation is so simple, its usually just 2-4 lines to create a complete
IPv6/ICMPv6 packet with the content of your choice.

Your basic structure you use is
  (thc_ipv6_hdr *)
e.g. 
  thc_ipv6_hdr *my_ipv6_packet;
  int my_ipv6_packet_len;
and you will never have to play with its options/fields.

Whenever you want to build an IPv6 packet, you just write:
  my_ipv6_packet = thc_create_ipv6_extended(interface, prefer, &my_ipv6_packet_len,
                          src6, dst6, ttl, length, label, class, version);
if something fails, it returns NULL (only if my_ipv6_packet_len or dst6 do
not exist or malloc fails).
The options to thc_create_ipv6_extended are:
 (char*) interface - the interface on which you want to send out the packet
 (int) prefer - either PREFER_LINK (to use the link local address) or
                PREFER_HOST to use a host IPv6 address, and 
                PREFER_GLOBAL to use a public (internet) IP6 address (default)
 (int *) &my_ipv6_packet_len - the size of the packet which will be created
 (unsigned char*) src6 - the source IP6 (OPTIONAL - will be selected if NULL)
 (unsigned char*) dst6 - the destination IP6 (in network format, 16 bytes long)
                         usually the result of thc_resolve6("ipv6.google.com");
 (int) ttl - the ttl of the packet (OPTIONAL - 0 will set this to 255)
 (int) length - the length which will be set in the header (OPTIONAL - 0 =
                real length)
 (int) label - the flow label (0 is fine)
 (int) class - the class of the packet (0 is fine)
 (int) version - the IP6 version (OPTIONAL - 0 will set this to version 6)
It returns NULL on errors or a malloc'ed structure on success.
free() it once you are done with it.

Now you can set extension headers on top of it:
  thc_add_hdr_route(my_ipv6_packet, &my_ipv6_packet_len, routers, routerptr);
  thc_add_hdr_fragment(my_ipv6_packet, &my_ipv6_packet_len, offset, more_frags,
                       id);
  thc_add_hdr_dst(my_ipv6_packet, &my_ipv6_packet_len, buf, buflen);
  thc_add_hdr_hopbyhop(my_ipv6_packet, &my_ipv6_packet_len, buf, buflen);
  thc_add_hdr_nonxt(my_ipv6_packet, &my_ipv6_packet_len, hdropt);
  thc_add_hdr_misc(my_ipv6_packet, &my_ipv6_packet_len, type, len, buf, buflen);
The functions explained:
 _route: Add a Routing Forwarding Header (like IP Source Routing)
  (int) routers - the number of routers in routerptr
  (char**) routerptr - a *char[routers + 1] struct with router destinations
                       in network format. See alive6.c for an example.
 _fragment: Add a Fragment Header
  (int) offset - the offset on which to the data should be written (note:
                 put the offset location in bytes here, not in byte octets)
  (int) more_frags - set to 0 if it is the fragement, 1 on all others
  (int) id - an ID for the packet (same for all fragments)
 _dst: Add a Destination Options Header
  (char*) buf - a char buffer. you have to control this buffer yourself with
                but you want to write into it.
  (int) buflen - the length of buf
 _hopbyhop: Add a Hop-By-Hop Header
  (char*) buf - a char buffer. you have to control this buffer yourself with
                but you want to write into it.
  (int) buflen - the length of buf
 _nonxt: Specify that there will be no following headers whatsoever
  (int) hdropt - this options is currently ignored
 _misc: Specify a miscelleanous header. Use this if you want to design an
        invalid or non-existing extension header.
  (int) type - The type ID to specify the header as
  (int) len - The length to advertise the header as (OPTIONAL - -1 sets this to
              the correct value)
  (char*) buf - a char buffer. you have to control this buffer yourself with
                but you want to write into it.
  (int) buflen - the length of buf
These functions return (int) 0 on success and -1 on error.

Finally you can add the stream or dgram headers.
  thc_add_icmp6(my_ipv6_packet, &my_ipv6_packet_len, type, code, flags, buf,
                buflen, checksum);
  thc_add_tcp(my_ipv6_packet, &my_ipv6_packet_len, source_port,
              destination_port, sequence_number, ack_number, flags, window_size
              urgent_pointer, options, optione_length, data, data_length);
  thc_add_udp(my_ipv6_packet, &my_ipv6_packet_len, source_port, 
              destination_port, checksum, data, data_length);
  thc_add_data6(my_ipv6_packet, &my_ipv6_packet_len, type, buf, buflen); 
 _icmp6: Add an ICMP6 packet header
  (int) type: the ICMP6 type
  (int) code: the ICMP6 code
  (int) flags: the ICMP6 flags
  (char*) buf - a char buffer. you have to control this buffer yourself with
                but you want to write into it.
  (int) buflen - the length of buf
 _tcp|_udp: Add an TCP or UDP header
  (ushort) source_port: source port
  (ushort) destination_port: destination port
  (uint) sequence_number: TCP sequence number
  (uint) ack_number: TCP acknowledgement number
  (ushort) checksum: UDP checksum, 0 = generate checksum (for TCP the checksum is always calculated)
  (uchar) flags: TCP flags: TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST, TCP_PSH, ...
  (uint) window_size: TCP window size
  (uint) urgent_pointer: TCP urgent pointer (usually 0)
  (char*) options: TCP options buffer, can be NULL
  (uint) options_length: the length of the TCP options buffer
  (char*) data: the data the protocol carries
  (uint) data_length: the length of the data buffer
 _data6: Add a miscellaneous header
  (int) type: the protocol ID
  (char*) buf - a char buffer. you have to control this buffer yourself with
                but you want to write into it.
  (int) buflen - the length of buf
These functions return (int) 0 on success and -1 on error.

Once you are done, you create and send the packet.
  thc_generate_pkt(interface, srcmac, dstmac, my_ipv6_packet,
                   &my_ipv6_packet_len);
  thc_send_pkt(interface, my_ipv6_packet, &my_ipv6_packet_len);
or combined into one function:
 thc_generate_and_send_pkt(interface, srcmac, dstmac, my_ipv6_packet,
                            &my_ipv6_packet_len);

 thc_generate_and_send_pkt: This generates the real and final IPv6 packet and
                           then sends it.
  (char*) interface - the interface to send the packet on
  (unsigned char*) srcmac - the source mac to use (in network format)
                            (OPTIONAL, the real mac is used if NULL)
  (unsigned char*) dstmac - the destination mac to use (in network format)
                            (OPTIONAL, the real mac is looked up if NULL)
The thc_generate_pkt and  thc_send_pkt together provide the same functionality.
You usually use these only if you do something like
  thc_generate_pkt(...);
  while(1) thc_send_pkt(...);
These functions return (int) 0 on success and -1 on error.

When you are done, free the memory with:
  thc_destroy_packet(my_ipv6_packet);

There are some important helper functions you will need:
  thc_resolve6(destinationstring);
    This resolves the IPv6 address or DNS name to an IPv6 network address.
    Use this for dst6 in thc_create_ipv6_extended(). The result has to be free'd when
    not needed anymore.
  thc_inverse_packet(my_ipv6_packet, &my_ipv6_packet_len);
    This clever functions switches source and destination address, exchanges
    the ICMP header type (ECHO REQUEST -> ECHO REPLY etc.) and recalculates
    the checksum. If you dont have an idea what this might be useful for,
    go and play with your xbox :-)

If you just want to do it very fast, there are some predefined ICMPv6 creator
functions which sends impc6 packets in just one line of code:
  thc_ping6(interface, src, dst, size, count);
  thc_neighboradv6(interface, src, dst, srcmac, dstmac, flags, target);
  thc_neighborsol6(interface, src, dst, target, srcmac, dstmac);
  thc_routeradv6(interface, src, dst, srcmac, default_ttl, managed, prefix,
                 prefixlen, mtu, lifetime);
  thc_routersol6(interface, src, dst, srcmac, dstmac);
  thc_toobig6(interface, src, srcmac, dstmac, mtu, my_ipv6_packet,
              my_ipv6_packet_len);
  thc_paramprob6(interface, src, srcmac, dstmac, code, pointer,
                 my_ipv6_packet, my_ipv6_packet_len);
  thc_unreach6(interface, src, srcmac, dstmac, icmpcode, my_ipv6_packet,
               my_ipv6_packet_len);
  thc_redir6(interface, src, srcmac, dstmac, newrouter, newroutermac,
             my_ipv6_packet, my_ipv6_packet_len);
  thc_send_as_fragment6(interface, src, dst, type, buf, buflen, frag_len);
These do what you expect them to do, so I am too lazy^H^H^H^H^Hbusy to
describe it in more details.

The following functions allocate memory for the result pointer, so remember
to free the result pointers from these functions once you do not need them
anymore:
  thc_ipv6_dummymac()
  thc_ipv62notation()
  thc_ipv62string()
  thc_string2ipv6()
  thc_string2notation()
  thc_resolve6()
  thc_get_own_ipv6()
  thc_get_own_mac()
  thc_get_multicast_mac()
  thc_get_mac()
  thc_lookup_ipv6_mac()
  thc_look_neighborcache()
  thc_generate_key()
  thc_generate_cga()
  thc_generate_rsa()

It helps a lot if you take a look at example usages. The best ones are
the tools from the thc-ipv6 package, especially implementation6.c and
fake_*6.c - have fun, and send back code, so the community can further
build on it.


DETECTION
=========
Most tools can easily be detected by an IDS or specialized detection software.
This is done on purpose to make rogue usage detection easier.
The tools either specify a fixed packet signature, or generically sniff for
packets (e.g. therefore also answering to ICMPv6 neighbor solitications which
are sent to a non-existing mac, and are therefore very easy to detect).
If you dont want this, change the code.


PATCHES, BUGS, HINTS, etc.
==========================
Send them to vh (at) thc (dot) org (and add "antispam" to the subject line)
Or submit via github: https://github.com/vanhauser-thc/thc-ipv6

Have fun!
