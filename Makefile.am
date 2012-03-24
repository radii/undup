bin_PROGRAMS = undup
undup_SOURCES = undup.c
undup_LDADD = -lcrypto

.PHONY: test
test:
	PATH=`pwd`:$$PATH `pwd`/test/runtest.sh
