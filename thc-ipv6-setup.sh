#!/bin/bash
ON=1
OK=""

test "$1" = "on" && { shift ; }
test "$1" = "enable" && { shift ; }
test "$1" = "en" && {  shift ; }
test "$1" = "ea" && { shift ; }

test "$1" = "off" && { ON=0 ; shift ; }
test "$1" = "no" && { ON=0 ; shift ; }
test "$1" = "non" && { ON=0 ; shift ; }
test "$1" = "disable" && { ON=0 ; shift ; }
test "$1" = "dis" && { ON=0 ; shift ; }

test "$2" = "off" && { ON=0 ; shift ; }
test "$2" = "no" && { ON=0 ; shift ; }
test "$2" = "non" && { ON=0 ; shift ; }
test "$2" = "disable" && { ON=0 ; shift ; }
test "$2" = "dis" && { ON=0 ; shift ; }

test "$1" = "-h" -o "$1" = "help" -o "$1" = "--help" -o -z "$1" && {
  echo "Syntax: $0 [no] command [options]"
  echo
  echo Available commands:
  echo "" ipv6 - enable ipv6 "(option: interface)"
  echo "" ra - "enables everything router advertisement (RA) (option: interface)"
  echo "" autoconf - perform autoconfiguration "(option: interface)"
  echo "" route - enables default route on RA "(option: interface)"
  echo "" dad - enable duplicate address detection "(option: interface)"
  echo "" privacy - enable the temporary address privacy extension "(option: interface)"
  echo "" forward - enables or disables forwarding
  echo "" redirfilter - sets ip6table to prevent sedning redirects "(option: interface)"
  echo "" src - enables or disables source routing and routing
  echo "" fwreset - reset the ipv6 firewalls
  echo
  echo prepend the keyword \"no\" to use reverse the function of the command
  OK=1
}

test "$1" = "srcroute" -o "$1" = "sourceroute" -o "$1" = "src" && {
  for i in /proc/sys/net/ipv6/conf/*; do 
    echo $ON > $i/accept_source_route
    echo $ON > $i/forwarding 
  done
  OK=1
}

test "$1" = "route" -o "$1" = "routing" -o "$1" = "forward" -o "$1" = "forwarding" && {
  for i in /proc/sys/net/ipv6/conf/*; do 
    echo $ON > $i/forwarding 
  done
  OK=1
}

test "$1" = "dad" && {
  INT=$2
  test -z "$2" && INT=all
  echo $ON > /proc/sys/net/ipv6/conf/$INT/accept_dad
  echo $ON > /proc/sys/net/ipv6/conf/$INT/dad_transmits
  OK=1
}

test "$1" = "redirfilter" -o "$1" = "redir" && {
  INT=""
  test -n "$2" && INT="-o $2"
  ip6tables -I OUTPUT $INT -p icmpv6 --icmpv6-type redirect -j DROP
  OK=1
}

test "$1" = "autoconf" -o "$1" = "autoconfig" -o "$1" = "autoconfiguration" -o "$1" = "slaac" && {
  INT=$2
  test -z "$2" && INT=all
  echo $ON > /proc/sys/net/ipv6/conf/$INT/autoconf
  OK=1
}

test "$1" = "privacy" -o "$1" = "priv" -o "$1" = "tempaddr" -o "$1" = "tempaddress" && {
  INT=$2
  test -z "$2" && INT=all
  echo $ON > /proc/sys/net/ipv6/conf/$INT/use_tempaddr 
  OK=1
}

test "$1" = "firewall" -o "$1" = "fwreset" -o "$1" = "resetfw" && {
  ip6tables -F
  ip6tables -X
  ip6tables -Z
  ip6tables -P INPUT ACCEPT
  ip6tables -P FORWARD ACCEPT
  ip6tables -P OUTPUT ACCEPT
  OK=1
}

test "$1" = "route" -o "$1" = "routes" && {
  INT=$2
  test -z "$2" && INT=all
  echo $ON > /proc/sys/net/ipv6/conf/$INT/accept_ra_defrtr
  OK=1
}

test "$1" = "ra" && {
  INT=$2
  test -z "$2" && INT=all
  echo $ON > /proc/sys/net/ipv6/conf/$INT/accept_ra
  echo $ON > /proc/sys/net/ipv6/conf/$INT/accept_ra_defrtr
  echo $ON > /proc/sys/net/ipv6/conf/$INT/accept_ra_pinfo
  echo $ON > /proc/sys/net/ipv6/conf/$INT/autoconf
  OK=1
}

test "$1" = "ipv6" -o "$1" = "ip6" && {
  INT="$2"
  test -z "$2" && { 
    INT=all
    test "$ON" = 0 && modprobe -v ipv6
    test "$ON" = 1 && rmmod ipv6
  }
  test "$ON" = 0 && RON=1
  test "$ON" = 1 && RON=0
  echo $RON > /proc/sys/net/ipv6/conf/$INT/disable_ipv6
  OK=1
}

test -z "$OK" && { echo Error: unknown command: $1 ; exit 1 ; }
 