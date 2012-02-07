CFLAGS = -O3 -Wall -g
OBJS = undup.o
LIBS = -lssl

.PHONY: test

all: undup

undup: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o undup $(LIBS)

test:
	PATH=`pwd`:$$PATH `pwd`/test/runtest.sh

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
