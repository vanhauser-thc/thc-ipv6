#!/bin/bash
test -z "$1" -o "$1" = "-h" && {
  echo "Syntax: $0 [-2] interface [target-link-local-address multicast-address]"
  echo If specified, the multicast address of the target will be dropped first.
  echo All multicast traffic will cease after a while.
  echo Specify -2 to use MLDv2.
  exit 1
}

X=""
test "$1" = "-2" && {
  X="2" 
  shift
}

while : ; do
  fake_mld${X}6 $i query :: ff02::1 1 fe80:: 11:22:33:44:55:66 33:33:00:00:00:02
  test -n "$3" fake_mld${X}6 $i del "$3" ff02::2 1 "$2" 11:22:33:44:55:66
  sleep 5
done
