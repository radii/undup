CFLAGS = -O3 -Wall -g
OBJS = undup.o

all: undup

undup: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o undup

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
