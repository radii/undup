/*
 * undup - compress data streams through backreferences
 *
 * Copyright (C) 2012 Andrew Isaacson <adi@hexapodia.org>
 *
 * This program is free software, licensed under the terms of the GNU GPL
 * version 2.  Please see the file COPYING for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <openssl/sha.h>

#define HASHSZ SHA256_DIGEST_LENGTH
#define BLOCKSZ 512

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

int o_decompress = 0;
char *o_output = NULL, *o_input = NULL;
int o_verbose = 0;

void die(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

void verbose(char *fmt, ...)
{
    va_list ap;
    struct timeval tv;

    if (o_verbose < 2) return;

    gettimeofday(&tv, 0);
    fprintf(stderr, "[%d.%06d] ", (int)tv.tv_sec, (int)tv.tv_usec);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

u64 htonll(u64 x)
{
    return
        (x & 0xffULL) << 56 |
        (x & 0xff00ULL) << 40 |
        (x & 0xff0000ULL) << 24 |
        (x & 0xff000000ULL) << 8 |
        (x & 0xff00000000ULL) >> 8 |
        (x & 0xff0000000000ULL) >> 24 |
        (x & 0xff000000000000ULL) >> 40 |
        (x & 0xff00000000000000ULL) >> 56;
}

void usage(const char *cmd)
{
    die("Usage: %s [-d] [-o output] [input]\n", cmd);
}

int hash(const void *buf, int n, void *outbuf)
{
    SHA256_CTX c;

    SHA256_Init(&c);
    SHA256_Update(&c, buf, n);
    SHA256_Final(outbuf, &c);
}

struct hashentry {
    struct hashentry *next;
    off_t off;
    char hash[HASHSZ];
};

struct hashtable {
    struct hashentry **e;
    int n;
};

struct hashtable *new_hashtable(int desired)
{
    struct hashtable *t = malloc(sizeof *t);

    if (!t) return NULL;

    if (desired < 1) desired = 1023;

    t->n = desired;
    t->e = calloc(sizeof *t->e, t->n);

    if (!t->e)
        goto fail;

    return t;
fail:
    free(t);
    return NULL;
}

off_t lookup(struct hashtable *t, char *sha)
{
    unsigned int idx = *(unsigned int *)sha % t->n;
    struct hashentry *e;

    for (e = t->e[idx]; e; e = e->next) {
        if (!memcmp(e->hash, sha, HASHSZ))
            return e->off;
    }
    return -1;
}

void insert(struct hashtable *t, off_t off, char *sha)
{
    unsigned int idx = *(unsigned int *)sha % t->n;
    struct hashentry *e;

    if (lookup(t, sha) != (off_t)-1)
        return;

    e = malloc(sizeof *e);
    if (!e) {
        verbose("failed to malloc hashentry, off = %lld\n", (long long)off);
        return;
    }

    e->off = off;
    memcpy(e->hash, sha, HASHSZ);
    e->next = t->e[idx];
    t->e[idx] = e;
}

#define CELLSZ 16
#define NUMCELL 32

#if CELLSZ * NUMCELL != BLOCKSZ
# error something wrong with CELLSZ NUMCELL and BLOCKSZ
#endif

struct undup {
    int fd;
    int curop;
    SHA256_CTX streamctx; // hash of complete stream
    SHA256_CTX blockctx;  // hash of current block
    off_t logoff;         // how many bytes have we represented so far
    off_t bakstart;       // postiion of start of active backref, or -1 if none
    off_t baklen;         // length of active backref
    int cellidx;
    int iovidx;
    u8 cells[NUMCELL][CELLSZ];
    struct iovec iov[NUMCELL];
};

#define OP_DATA 0x01

struct data_cell {
    union {
        u8 op;
        u32 len;
    };
    u8 hash[12];
};

#define OP_BACKREF 0x02

struct backref_cell {
    union {
        u8 op;
        u64 pos;
    };
    u32 len;
    u8 zeros[4];
};

#define OP_TRAILER 0xff

struct und_trailer {
    union {
        u8 op;
        u64 len;
    };
    u8 hash[HASHSZ];
};


struct undup_funcs {
    void (*finalize)(struct undup *);
};

void und_backref_finalize(struct undup *und);
void und_data_finalize(struct undup *und);
void und_trailer_finalize(struct undup *und);

struct undup_funcs undfuncs[] = {
    [OP_DATA] = { und_data_finalize },
    [OP_BACKREF] = { und_backref_finalize },
    [OP_TRAILER] = { und_trailer_finalize },
};

struct undup *new_undup_stream(int fd)
{
    struct undup *und = calloc(sizeof *und, 1);

    if (!und) return NULL;

    und->fd = fd;
    SHA256_Init(&und->streamctx);
    und->bakstart = -1;

    return und;
}

void und_trailer(struct undup *und)
{
    int r;
    struct und_trailer tr;

    SHA256_Final(tr.hash, &und->streamctx);
    tr.len = htonl(und->logoff);
    tr.op = OP_TRAILER;
    r = write(und->fd, &tr, sizeof(tr));
    if (r == -1)
        die("write: %s\n", strerror(errno));
    if (r < sizeof(tr))
        die("short write on trailer: wrote %d of %d\n", r, (int)sizeof(tr));
    und->curop = OP_TRAILER;
}

void und_trailer_finalize(struct undup *und)
{
    die("Botch: und_trailer_finalize called.\n");
}

void und_flush(struct undup *);

void end_undup_stream(struct undup *und)
{
    int r;

    und_flush(und);
    und_trailer(und);

    r = close(und->fd);
    if (r != 0)
        die("close: %s\n", strerror(errno));
}

void und_flush(struct undup *und)
{
    int i, numiov;
    struct iovec iov[NUMCELL + 1];
    ssize_t r, expected;

    if (und->cellidx == 0)
        return;

    /*
     * An incomplete metadata block should be padded with zero-length
     * op_data cells.
     */
    memset(und->cells + und->cellidx, 0, (NUMCELL - und->cellidx) * CELLSZ);
    for (i = und->cellidx; i < NUMCELL; i++)
        und->cells[i][0] = OP_BACKREF;

    memcpy(iov + 1, und->iov, und->iovidx);
    i = und->cellidx;
    iov[i].iov_base = und->cells;
    iov[i].iov_len = BLOCKSZ;
    numiov = und->iovidx + 1;

    expected = BLOCKSZ;
    for (i=0; i<und->iovidx; i++) {
        expected += und->iov[i].iov_len;
    }

    r = writev(und->fd, iov, numiov);
    if (r == -1)
        die("write: %s\n", strerror(errno));
    if (r < expected)
        die("Short write on output (wrote %lld of %lld)\n", 
            (long long)r, (long long)expected);

    /* reset for next frame */
    memset(und->cells, 0, sizeof(und->cells));
    memset(und->iov, 0, sizeof(und->iov));
    und->cellidx = 0;
    und->iovidx = 0;

}

void und_queue_cell(struct undup *und, void *cell, size_t cellsz)
{
    int i = und->cellidx++;

    if (cellsz != CELLSZ)
        die("Botch, %d != %d\n", cellsz, CELLSZ);

    memcpy(und->cells[i], cell, cellsz);
    if (und->cellidx == NUMCELL) {
        und_flush_frame(und);
    }
}

void und_prep(struct undup *und, int opcode, void *buf, int len)
{
    SHA256_Update(&und->streamctx, buf, len);
    SHA256_Update(&und->blockctx, buf, len);
    und->logoff += len;

    if (und->curop == opcode)
        return;

    undfuncs[und->curop].finalize(und);
    und->curop = opcode;

    SHA256_Init(&und->blockctx);
}

void und_backref_cell(struct undup *und, off_t oldoff,
                      char *buf, int len, char *sha)
{
    und_prep(und, OP_BACKREF, buf, len);

    if (und->bakstart + und->baklen == oldoff && len == BLOCKSZ) {
        /* extend existing backref */
        und->prevbak += len;
    } else {
        und->prevbak = oldoff + len;
    }
}

void und_backref_finalize(struct undup *und)
{
    struct backref_cell br;
    char sha[HASHSZ];

    br.pos = htonll(und->bakstart);
    if (br.op != 0)
        die("unpossible, start = %lld pos = 0x%llx op = %d\n",
            und->bakstart, br.pos, br.op);

    br.op = OP_BACKREF;
    br.len = htonl(und->baklen);

    SHA256_Final(sha, &und->blockctx);
    memcpy(br.hash, sha, sizeof(br.hash));
    und_queue_cell(und, &br, sizeof(br));
}

void und_data_cell(struct undup *und, char *buf, int len)
{
    int i, n;
    void *p;

    und_prep(und, OP_DATA, buf, len);

    i = und->iovidx;
    n = und->iov[i].iov_len;
    p = realloc(und->iov[i].iov_base, n + len);
    memcpy((u8 *)p + n, buf, len);
}

void und_data_finalize(struct undup *und)
{
    struct data_cell da;
    char sha[HASHSZ];
    int len = und->iov[und->iovidx].iov_len;
    int numblock = len / BLOCKSZ + !!(len % BLOCKSZ);

    da.len = htonl(numblock);
    if (da.op != 0)
        die("unpossible, numblock = %d len = %x op = %d\n",
            numblock, da.len, da.op);
    da.op = OP_DATA;
    SHA256_Final(sha, &und->blockctx);
    memcpy(da.hash, sha, sizeof(da.hash));
    und_queue_cell(und, &da, sizeof(da));
    und->iovidx++;
}

int main(int argc, char **argv)
{
    int c, n;
    int infd, outfd;
    int bufsz = BLOCKSZ;
    char *buf;
    struct hashtable *table = new_hashtable(0);
    struct undup *und;

    while ((c = getopt(argc, argv, "do:v")) != EOF) {
        switch (c) {
            case 'd':
                o_decompress = 1;
                break;
            case 'o':
                o_output = optarg;
                break;
            case 'v':
                o_verbose++;
                break;
            default:
                usage(argv[0]);
        }
    }

    if (argc > optind) {
        o_input = argv[optind];
    }

    if (o_input == NULL) {
        infd = 0;
    } else {
        if ((infd = open(o_input, O_RDONLY)) == -1)
            die("%s: %s\n", o_input, strerror(errno));
    }
    if (o_output == NULL) {
        outfd = 1;
    } else {
        if ((outfd = open(o_output, O_RDWR|O_CREAT|O_EXCL, 0666)) == -1)
            die("%s: %s\n", o_output, strerror(errno));
    }

    buf = malloc(bufsz);
    if (!buf) die("malloc(%d): %s\n", bufsz, strerror(errno));

    und = new_undup_stream(outfd);
    if (!und) die("new_undup_stream: %s\n", strerror(errno));

    while ((n = read(infd, buf, bufsz)) > 0) {
        char sha[HASHSZ];

        hash(buf, n, sha);
        oldoff = lookup(table, sha);

        if (oldoff != (off_t)-1 && len == BLOCKSZ) {
            und_backref_cell(und, oldoff, buf, n, sha);
        } else {
            und_data_cell(und, buf, n);
        }
    }
    if (n == -1)
        die("read: %s\n", strerror(errno));

    end_undup_stream(und);

    return 0;
}
