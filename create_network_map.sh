#!/bin/bash
test -z "$1" -o '!' -e "$1" && {
  echo "Syntax: $0 file1 file2 file3 file4 ... > map.gv"
  echo Creates a GV file for use with Graphviz to create a network topology map
  echo file1 must have per line one entry only.
  echo "Afterwards run it like: dot -Tjpg map.gv > map.jpg"
  exit 1
}

echo "digraph my_test {"
echo "  ratio = \"auto\";"
echo "  micross = 2.0;"
echo "  label = \"network topology map\";"
#echo '  #"host_entry_example" [shape=box];'

for i in $*; do
  FIRST=""
  CNT=1
  while read l ; do
    test "$l" = "???" && l="$CNT-???-$CNT"
    test -n "$FIRST" && {
      echo "  \"$FIRST\" -> \"$l\";"
    }
    CNT=`expr $CNT + 1`
    FIRST="$l"
  done < "$i"
done | sort | uniq

echo "}"
