#!/bin/bash

testdir=`dirname $0`

case "$testdir" in
/*) ;;
*) testdir=`pwd`/$testdir ;;
esac

d=`mktemp -d`
cd $d

passes=0
fails=0

for t in $testdir/t*[^~]; do
    printf "_%-40s_" `basename ${t/t/}`_ | sed 's/ /./g; s/_/ /g'
    sh $t
    res=$?
    if [[ $res == 0 ]]; then
        echo "PASS"
        ((passes++))
    else
        echo "FAIL"
        ((fails++))
    fi
done

echo "passed: $passes failed: $fails"
if [[ $fails == 0 ]]; then
    exit 0
else
    exit 1
fi
