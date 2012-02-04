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

#include <unistd.h>

#include <openssl/sha.h>

#define HASHSZ SHA256_DIGEST_LENGTH
#define BLOCKSZ 4096

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

void usage(const char *cmd)
{
    die("Usage: %s [-d] [-o output] [input]\n", cmd);
}

int hash(const char *buf, int n, char *outbuf)
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

struct undup {
    int fd;
    SHA256_CTX streamctx;
    SHA256_CTX blockctx;
    off_t logoff;       // how many bytes have we represented so far
    off_t bakstart;     // postiion of start of active backref, or -1 if none
    off_t baklen;       // length of active backref
};

struct undup *new_undup_stream(int fd)
{
    struct undup *und = malloc(sizeof *und);

    if (!und) return NULL;

    und->fd = fd;
    SHA256_Init(&und->streamctx);
    und->logoff = 0;
    und->bakstart = -1;

    return und;
}

#define OP_BACKREF 0x02

struct backref_cell {
    union {
        u8 op;
        u64 pos;
    };
    u32 len;
    u8 hash[20];
};

void finalize_backref(struct undup *und)
{
    struct backref_cell br;
    char backref[sizeof br];
    char sha[HASHSZ];

    br->pos = ntohll(und->bakstart);
    if (br->op != 0) die("unpossible, pos = %lld op = %d\n", br->pos, br->op);
    br->op = OP_BACKREF;
    br->len = ntohl(und->baklen);

    SHA256_Final(&und->blockctx, sha);
}

void und_backref_cell(struct undup *und, off_t oldoff, char *buf, int len, char *sha)
{
    SHA256_Update(&und->streamctx, buf, len);
    und->logoff += len;

    if (und->bakstart + und->baklen == oldoff && len == BLOCKSZ) {
        /* extend existing backref */
        und->prevbak += len;
    } else {
        und->prevbak = oldoff + len;
        SHA256_Init(&und->blockctx);
    }
    SHA256_Update(&und->blockctx, buf, len);
}

void und_data_cell(struct undup *und, char *buf, int len)
{


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

    finalize_undup_stream(und);

    return 0;
}
