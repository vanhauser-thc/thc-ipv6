#!/bin/bash

test -z "$1" -o -z "$2" -o "$1" = "-h" && { echo Syntax: $0 interface ALIVE-FILE; echo Creates a GraphViz .gv file from the file containing alive IPv6 addresses. ; echo Several files will be created in the same directory as the input file. ; exit 1; }

echo Ping scanning list ...
alive6 -p -i "$2" $1 | grep Alive: | grep echo-reply | awk '{print$2}' > "$2".pingable

echo Extracting one target from every network ...
for i in `extract_networks6.sh "$2".pingable | sort -u | sed 's/:$//'`; do
  grep "^$i" "$2".pingable | head -n 1
done > "$2".traceable

echo Tracerouting targets ...
for i in `cat "$2".traceable`; do
  trace6 $1 $i > $i.trace
  trace62list.sh $i.trace > $i.list
done

echo Creating GraphViz GV file
create_network_map.sh *.list > "$2".gv

echo Creating JPG file
dot -Tjpg "$2".gv > "$2".jpg

echo Done, JPG is in $2.jpg and GraphViz is in $2.gv
