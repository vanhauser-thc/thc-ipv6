#!/bin/bash

REMOVE="tr X X"
test "$1" = "-r" && { REMOVE='grep -v "?"' ; shift ; }

test -z "$1" -o '!' -e "$1" && { 
  echo "Syntax: $0 trace6_output_file [skip-cnt] > foo.out"
  echo "Prepares a trace6 output file for the network topology map generation tool"
  echo "(create_network_map.sh). If skip-cnt is defined, the amount of initial hops are skipped"
#  echo "If the -r option is defined, all ??? entries are removed"
  exit 1
}

SKIP=""
FILE="$1"
test -n "$2" && SKIP=$2

{ 
  test -z "$SKIP" && grep -E '^ *[0-9]+: ' "$FILE"
  test -z "$SKIP" || {
    LINES=`grep -E '^ *[0-9]+: ' "$FILE" | wc -l`
    DUMP=`expr $LINES - $SKIP`
    test "$DUMP" -gt 0 && grep -E '^ *[0-9]+: ' "$FILE" | tail -n $DUMP
  }

} | tr '\t' ' ' | sed 's/ *\[.*//' | awk '{print$2" "$3}' | sed 's/ ()//' | tr '\n' '#' | sed 's/[??? #]*??? #$/#/' | sed 's/!!! *#$/#/'  | tr '#' '\n'
