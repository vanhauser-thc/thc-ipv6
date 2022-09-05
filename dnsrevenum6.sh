#!/bin/bash
test -z "$1" -o "$1" = "-h" && {
  echo "Syntax: $0 ipv6-address[/prefixlength] [domain]"
  echo scans the reverse DNS entries of the /48 of the ipv6 address on the
  echo responsible dns server.
  echo if you get a \"no SOA entry found\" error message, please supply the
  echo corresponding domain name as an extra option.
  echo requires \"dig\" installed.
  exit 1
}

which dig > /dev/null 2>&1 || { echo Error: dig not found in PATH ; exit 1 ; }

EXTRA=""
PLEN=""
PREFIX=$1
#test -n "$2" && PLEN=$2
test -n "$2" && EXTRA="$2"

echo $PREFIX | grep -q / && {
  PREFIX=`echo $1 | sed 's/\/.*//'`
  #test -z "$PLEN" &&
  PLEN=`echo $1 | sed 's/.*\///'`
}

test -z "$PLEN" && PLEN=48

which dig > /dev/null 2>&1 || { echo Error: you need the dig command in your path ; exit 1 ; }

DOMAIN=`dig -x $PREFIX soa | grep SOA | grep -v '^;' | tr '\t' ' ' | sed 's/.*SOA *//' | sed 's/ .*//'`
test -z "$DOMAIN" && DOMAIN=`dig @8.8.8.8 -x $PREFIX soa | grep SOA | grep -v '^;' | tr '\t' ' ' | sed 's/.*SOA *//' | sed 's/ .*//'`
test -z "$DOMAIN" -a -n "$EXTRA" && DOMAIN=`dig $EXTRA ns | grep -E -v '^;' | grep -E -w NS | grep -E -w IN | awk '{print$5}'`
test -z "$DOMAIN" && { echo Error: no SOA entry found for domain ; exit 1 ; }

X=`echo ${PREFIX}-$PLEN| sed 's/\.$//' | tr : _`

for i in $DOMAIN; do
  echo Enumerating $PREFIX/$PLEN on server $i ...
  Y=`echo $i | sed 's/\.$//'`
  dnsrevenum6 $i $PREFIX/$PLEN > $X-$Y.revenum
  grep -q Found: $X-$Y.revenum && echo Reverse DNS information saved to $X-$Y.revenum
  grep -q Found: $X-$Y.revenum || rm -f $X-$Y.revenum
done
