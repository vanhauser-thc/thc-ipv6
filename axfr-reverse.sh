#!/bin/bash
test -z "$1" -o "$1" = "-h" && { echo "Syntax: $0 ipv6-address [prefixlength]"; echo "data is saved to \$domain-\$ns.zone"; echo if there are dns soa problems and the prefix length is not 48 you can specify it as an extra option on the command line ; exit 1; } 

which dig > /dev/null 2>&1 || { echo Error: you need the dig command in your path ; exit 1 ; }

PLEN=48
FOO=$1
test -n "$2" && PLEN=$2
echo -- $1 | grep -q / && FOO=`echo $1 | sed 's/\/.*//'`
dig 1.0.0.1.0.0.0.0.3.0.0.2.ip6.arpa. ns | grep -q '^1\.0.*SOA' || DNS="@8.8.8.8"
DOMAIN=`dig -x $FOO soa | grep -w SOA | awk '{print$1}' | grep -v ';'`
test -z "$DOMAIN" && DOMAIN=`dig @8.8.8.8 -x $FOO ns | grep -w SOA | awk '{print$1}' | grep -v ';'`
test -z "$DOMAIN" && { echo Error: could not get SOA entry for $FOO ; exit 1 ; }
test -z "$DOMAIN" -a -n "$PLEN" && {
  CHARS=`expr '(' 132 - $PLEN ')' / 2`
  DOMAIN=`dig -x $FOO soa | grep -w SOA | awk '{print$1}' | grep -E '^;' | awk '{print$1}' | cut -b ${CHARS}- `
}

X=`echo $FOO | sed 's/\.$//' | tr : _`

for j in `dig $DOMAIN ns | grep -w NS | grep -w IN | grep -v '^;' | awk '{print$5}'`; do
  echo Trying reverse zone transfer of $DOMAIN on $j ...
  Y=`echo $j | sed 's/\.$//'`
  dig @$j $DOMAIN axfr > $X-$Y.zone
  grep -w NS $X-$Y.zone | grep -v '^;' | grep -q NS && echo Zone saved to $X-$Y.zone
  grep -w NS $X-$Y.zone | grep -v '^;' | grep -q NS || rm -f $X-$Y.zone
done
