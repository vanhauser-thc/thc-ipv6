#!/bin/bash
LOOP=
test "$1" = "-i" && { LOOP=yes ; shift ; }
test -z "$1" -o "$1" = "help" && {
  echo 'Local IPv6 Discovery Script (c) 2022 by van Hauser <vh@thc.org> www.github.com/vanhauser-thc/thc-ipv6'
  echo
  echo Syntax: $0 [-i] INTERFACE
  echo
  echo The tool will use all local host discovery methods and output it to stdout as well as to the file INTERFACE-YYMMDDHHMMSS.log
  echo The -i option will loop forever until the script is terminated
  exit 1
}
INT=$1
ifconfig $INT | grep -q inet6 || {
  echo Error: interface $INT not found or ipv6 not enabled >&2
  exit 1
} 
FILE=${INT}-`date +%Y%m%d%H%M%S`.log
trap ' kill -TERM `cat .$FILE.pid` ; rm -f .$FILE.pid ; exit 0 ' 1 2 3 13 15
{ 
  passive_discovery6 -s -R 3000:: $INT &
  PID=$!
  echo $PID > .$FILE.pid
} | tee $FILE &
GO=yes
while [ "$GO" = yes ] ; do
  fake_mld6 $INT query
  alive6 -l $INT
  dump_router6 $INT
  fake_router26 -A 3000::/64 -a 2 -l 2 -n 1 -p low $INT
  ifconfig $INT | grep -iq global && alive6 $INT
  node_query6 $INT ff02::1
  fake_mld26 $INT query
  test "$LOOP" = yes && sleep 20
  test "$LOOP" = yes || GO=no
done > /dev/null 2>&1
sleep 5
trap '' 0 1 2 3 13 15
kill -TERM `cat .$FILE.pid`
rm -f .$FILE.pid
