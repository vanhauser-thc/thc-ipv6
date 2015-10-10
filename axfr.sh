#!/bin/bash
test -z "$1" -o "$1" = "-h" && { echo Syntax: $0 domain ; echo data is saved to domain-ns.zone ; exit 1; } 

which dig > /dev/null 2>&1 || { echo Error: you need the dig command in your path ; exit 1 ; }

DNS=""
dig 1.0.0.1.0.0.0.0.3.0.0.2.ip6.arpa. ns | grep -q '^1\.0.*SOA' || DNS="@8.8.8.8"
DOMAIN=$1
X=`echo $1 | sed 's/\.$//'`
echo $1 | grep -q '\.$' || DOMAIN=$DOMAIN.

for j in `dig $DNS $DOMAIN ns | grep -w NS | grep -w IN | grep -v '^;' | awk '{print$5}'`; do
  echo Trying zone transfer of $DOMAIN on $j ...
  Y=`echo $j | sed 's/\.$//'`
  dig @$j $DOMAIN axfr > $X-$Y.zone
  grep -w NS $X-$Y.zone | grep -v '^;' | grep -q NS && echo Zone saved to $X-$Y.zone
  grep -w NS $X-$Y.zone | grep -v '^;' | grep -q NS || rm -f $X-$Y.zone
done
