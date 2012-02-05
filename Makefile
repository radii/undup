CFLAGS = -O3 -Wall -g
OBJS = undup.o
LIBS = -lssl

all: undup

undup: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o undup $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
