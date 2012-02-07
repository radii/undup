#!/bin/sh

set -e

d=`mktemp -d`
cd $d

perl -e 'print("a" x 512);
         print("b" x 512);
         print("c" x 512);
         print("a" x 512);
         print("c" x 512);
         print("d" x 512);' > foo

set -x

undup foo -o foo.undup
undup -vvvvv -d -o result foo.undup
cmp foo result
