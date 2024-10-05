#!/bin/sh
#
# Tests to make sure deeply nested types error out before they cause an overflow
#
# @TEST-EXEC: /bin/sh %INPUT %INPUT.hlt
# @TEST-EXEC-FAIL: ${HILTIC} -p %INPUT.hlt > output 2>&1
# @TEST-EXEC: btest-diff output

filename=$1
NUM_ITERATIONS=1005

if test $# -ne 1; then
    echo >&2 "No filename provided"
    exit 1
fi

echo "module Overflow {" >> "$filename"

i=0
while [ $i -le $NUM_ITERATIONS ]; do
    echo "type Data$i = Data$((i+1));" >> "$filename"
    i=$((i+1))
done

# Doesn't matter, just make it resolve
echo "type Data$i = uint<8>;" >> "$filename"

echo "}" >> "$filename"
