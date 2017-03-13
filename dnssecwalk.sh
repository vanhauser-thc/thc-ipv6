#!/bin/bash
test -z "$1" -o "$1" = "-h" && { echo "Syntax: $0 [-a] domain" ; echo will try dnssecwalk on all nameservers until one is found, or all if -a is given as option ; exit 1 ; } 

which dig > /dev/null 2>&1 || { echo Error: you need the dig command in your path ; exit 1 ; }

DNS=""
dig 1.0.0.1.0.0.0.0.3.0.0.2.ip6.arpa. ns | grep -q '^1\.0.*SOA' || DNS="@8.8.8.8"
ALL=""
test "$1" = "-a" && { ALL=1 ; shift ; }
DOMAIN=$1
echo $1 | grep -q '\.$' || DOMAIN=$1.
FILE=`echo $DOMAIN|sed 's/\.$//'`
OK=""

for j in `dig $DNS $DOMAIN ns | grep -w NS | grep -w IN | grep -v ';' | awk '{print$5}'`; do
  SERVER=`echo $j|sed 's/\.$//'`
  test -z "$OK" && { 
    echo Trying $j ...
    dnssecwalk -t -6 $j $DOMAIN > $SERVER-$FILE.dnssecwalk
    grep -q Found: $SERVER-$FILE.dnssecwalk && OK=1
    test -n "$OK" && echo Dnssecwalk succeeded, saved to $SERVER-$FILE.dnssecwalk
    test -n "$OK" || rm -f $SERVER-$FILE.dnssecwalk
    test -n "$ALL" && OK=""
  }
done
