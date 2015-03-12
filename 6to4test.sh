#!/bin/bash
test -z "$1" -o "$1" = "-h" -o -z "$2" && {
  echo Syntax: $0 interface ipv4address
  echo This little script tests if the IPv4 target has a dynamic 6to4 tunnel active
  echo Requires address6 and thcping6 from thc-ipv6
  exit 1
}

HEX=`address6 $2 | head -n 2 | tail -n 1 | sed 's/.*:://'`
test -z "$HEX" && { echo Error: could not generate ipv6 address from ipv4 address $1 ; exit 1 ; }
TARGET="2002:$HEX::$HEX"

echo thcping6 $1 $TARGET
thcping6 $1 $TARGET
