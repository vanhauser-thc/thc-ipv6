#!/bin/bash

test -z "$1" -o "$1" = "-h" -o -z "$4" && {
  echo "Syntax: $0 [-s src4] interface ipv4-to-6-gw ipv6src ipv6dst [port]"
  echo
  echo "Options:"
  echo "  -s src4   spoofs the specified IPv4 source ddress"
  echo
  echo "Send an IPv6 packet to an IPv4 6to4 gateway. If a port is specified, a UDP"
  echo "packet is sent, otherwise an ICMPv6 ping."
  echo "Note: the packet is sent to the IPv4 default gateway!"
  exit 1
}

SRC4=
test "$1" = "-s" && { shift ; SRC4=$1 ; shift ; }
test -z "$4" && SRC4=`ifconfig $1 | grep "inet addr:" | awk -F: '{print$2}' | sed 's/ .*//'`

MAC4=`ifconfig $1 | grep "^$1" | sed 's/.*HWaddr //i' | tr -d ' \t'`

DST4=$2
ROUTER4=`ip -4 route show | grep $1 | grep via | grep default | awk '{print$3}'` 
MAD4=`arp -a -v -n | grep "($ROUTER4)" | awk '{print$4}'`

PORT=
test -n "$5" && PORT="-U $5"

echo export THC_IPV6_6IN4=$MAC4,$MAD4,$SRC4,$DST4
echo thcping6 $PORT $1 $3 $4
