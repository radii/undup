#! /bin/sh -e

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

rm -f config.cache
aclocal
autoconf
autoheader
automake -a --add-missing -Wall
