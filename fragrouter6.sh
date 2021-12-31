#!/bin/bash
#
# fragrouter6 startup script
#

test -z "$1" -o "$1" = "-h" -o -z "$2" && {
  echo "fragrouter6 startup script  (c) 2022 by van Hauser / THC"
  echo
  echo "Syntax: $0 [fragrouter6-options] interface evasion-mode [ip6tables-rule]"
  echo
  echo "fragrouter6-options - additional options for fragrouter, e.g. -e, -t etc."
  echo "interface - the interface of the direction to the target"
  echo "evasion-mode - the evasion mode number (see fragrouter6 help output)"
  echo "ip6tables-rule - rule definition of the traffic you want to have evasion on."
  echo "                 e.g.: -p tcp -d targetipv6 --dport 80"
  exit 0
}

VAR=
while [ '!' -d "/proc/sys/net/ipv6/conf/$1" ]; do
  VAR="${VAR}$1 "
  shift;
done
INT=$1
MODE=$2
shift ; shift

test -z "$1" && echo "Warning: no ip6table target definition defined - will manipulate ALL traffic!"

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
$IPTABLES -N THC_NFQUEUE >/dev/null 2>&1
# Send all hooked table traffic to new table
$IPTABLES -I POSTROUTING -j THC_NFQUEUE $* || {
  echo Error: your supplied ip6tables definitions are invalid, resetting
  $IPTABLES -X THC_NFQUEUE >/dev/null 2>&1
  exit 1
}
# Set incoming exceeded drop rule to prevent connection resets
$IPTABLES -I INPUT -p icmpv6 --icmpv6-type 3 -i $INT -j DROP
# Send all traffic from the new table to NFQUEUE table
$IPTABLES -I THC_NFQUEUE -p all -j NFQUEUE
# Fix loopback traffic
$IPTABLES -I INPUT -p all -i lo -j ACCEPT
$IPTABLES -I OUTPUT -p all -o lo -j ACCEPT

# Start fragrouter6
fragrouter6 -v $VAR $INT $MODE

# Drop fix for loopback traffic
$IPTABLES -D INPUT -p all -i lo -j ACCEPT
$IPTABLES -D OUTPUT -p all -o lo -j ACCEPT
# Delete incoming exceeded drop rule
$IPTABLES -D INPUT -p icmpv6 --icmpv6-type 3 -i $INT -j DROP
# Restore hooked table
$IPTABLES -D POSTROUTING -j THC_NFQUEUE $*
# Drop rules from nfq-test-1 tables
$IPTABLES -F THC_NFQUEUE
# Delete the table
$IPTABLES -X THC_NFQUEUE >/dev/null 2>&1
if [ "$?" != "0" ]; then
	echo "Unable to drop THC_NFQUEUE!"
	echo "You need to do this manually!"
fi	

echo
echo done.
