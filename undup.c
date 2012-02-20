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

#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <openssl/sha.h>

#define HASHSZ SHA256_DIGEST_LENGTH
#define BLOCKSZ 512
#define UNDUP_MAGIC 0x756e6475

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

int o_decompress = 0;
char *o_output = NULL, *o_input = NULL;
int o_verbose = 0;
u64 o_maxmem = 0;

void die(char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
void verbose(char *fmt, ...) __attribute__((format(printf, 1, 2)));
void debug(char *fmt, ...) __attribute__((format(printf, 1, 2)));

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

void debug(char *fmt, ...)
{
    va_list ap;
    struct timeval tv;

    if (o_verbose < 3) return;
    gettimeofday(&tv, 0);
    fprintf(stderr, "[%d.%06d] ", (int)tv.tv_sec, (int)tv.tv_usec);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

double rtc(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

/* returns the memory usage of PID, in MiB */
u64 get_mem_usage(int pid)
{
    char buf[100];
    FILE *f;
    int x;

    snprintf(buf, sizeof buf, "/proc/%d/status", pid);
    if ((f = fopen(buf, "r")) == NULL)
        return 0;

    while (fgets(buf, sizeof buf, f) != NULL) {
        if (sscanf(buf, "VmSize: %d", &x) == 1) {
            break;
        }
    }
    fclose(f);
    return x / 1024;
}

/* what a crock. */
u64 htonll(u64 x)
{
    u64 ret;
    u8 *buf = (u8 *)&ret;

    buf[0] = x >> 56;
    buf[1] = x >> 48;
    buf[2] = x >> 40;
    buf[3] = x >> 32;
    buf[4] = x >> 24;
    buf[5] = x >> 16;
    buf[6] = x >> 8;
    buf[7] = x;
    return ret;
}

u64 ntohll(u64 x)
{
    return htonll(x);
}

void usage(const char *cmd)
{
    die("Usage: %s [-d] [-o output] [input]\n", cmd);
}

void hash(const void *buf, int n, void *outbuf)
{
    SHA256_CTX c;

    SHA256_Init(&c);
    SHA256_Update(&c, buf, n);
    SHA256_Final(outbuf, &c);
}

struct hashentry {
    off_t off;
    char hash[HASHSZ];
};

struct hashtable {
    struct hashentry **e;
    int *num;
    size_t maxmem, size, startmem;
    int n;
    unsigned int cursor;
};

/*
 * Creates a new hashtable with DESIRED buckets.  If DESIRED == 0 a useful
 * default size is chosen.  If MAXMB > 0, it sets a limit on the maximum 
 * memory consumption of the hashtable, measured in megabytes.  When the limit
 * is reached, previous entries are overwritten.
 */
struct hashtable *new_hashtable(int desired, size_t maxmb)
{
    struct hashtable *t = calloc(sizeof *t, 1);

    if (!t) return NULL;

    if (desired < 1) desired = 65537;

    t->n = desired;
    t->e = calloc(sizeof *t->e, t->n);
    t->num = calloc(sizeof *t->num, t->n);
    if (maxmb > 0) {
        t->maxmem = maxmb * 1024 * 1024;
    }
    t->startmem = get_mem_usage(getpid());

    if (!t->e || !t->num)
        goto fail;

    return t;
fail:
    free(t->e);
    free(t->num);
    free(t);
    return NULL;
}

void insert(struct hashtable *t, int idx, off_t off, u8 *sha)
{
    struct hashentry *b;
    struct hashentry *e;

    if (t->maxmem && t->size > t->maxmem && t->num[idx] > 1) {
        /* beyond size limit, pick entry to overwrite */
        debug("hashsz %d MB limit %d MB overwrite idx %d num %d cursor %u\n",
                (int)(t->size / 1024 / 1024), (int)(t->maxmem / 1024 / 1024),
                idx, t->num[idx], t->cursor);
        e = t->e[idx] + (t->cursor++ % t->num[idx]);
    } else {
        b = realloc(t->e[idx], (1 + t->num[idx]) * sizeof *b);
        t->size += sizeof *b;
        if (!b) {
            verbose("failed to realloc hashentry, off = %lld\n",
                    (long long)off);
            return;
        }
        e = b + t->num[idx];
        t->e[idx] = b;
        t->num[idx]++;
    }

    e->off = off;
    memcpy(e->hash, sha, HASHSZ);

    debug("insert idx %d off %llx hash %02x%02x%02x%02x e %p num %d\n",
          idx, (long long)off, sha[0], sha[1], sha[2], sha[3], e, t->num[idx]);
}

off_t lookup_insert(struct hashtable *t, u8 *sha, off_t newoff)
{
    unsigned int idx = *(unsigned int *)sha % t->n;
    struct hashentry *e = t->e[idx];
    int i;

    debug("lookup idx %d e %p\n", idx, t->e[idx]);

    for (i = 0; i < t->num[idx]; i++, e = t->e[idx] + i) {
        if (!memcmp(e->hash, sha, HASHSZ))
            return e->off;
    }
    insert(t, idx, newoff, sha);
    return -1;
}

void hash_stats(struct hashtable *t, FILE *f)
{
    int i;
    int numentries = 0;
    int maxbucket = 0;
    struct hashentry *e;
    int mb, memused;

    for (i=0; i<t->n; i++) {
        int len = t->num[i];

        numentries += len;
        if (len > maxbucket)
            maxbucket = len;
    }
    mb = sizeof(*e) * numentries / 1024 / 1024;
    memused = get_mem_usage(getpid()) - t->startmem;
    fprintf(f, "hash: %d entries (%d MiB / %d MiB, %.1f%% VM efficency), avg bucket %.1f, max bucket %d\n",
            numentries, mb, memused, mb * 100. / memused,
            numentries * 1. / t->n, maxbucket);
}

#define CELLSZ 16
#define NUMCELL 32

#if CELLSZ * NUMCELL != BLOCKSZ
# error something wrong with CELLSZ NUMCELL and BLOCKSZ
#endif

struct undup {
    int fd;
    int curop;
    struct timeval starttime;
    SHA256_CTX streamctx; // hash of complete stream
    SHA256_CTX blockctx;  // hash of current block
    off_t logoff;         // how many bytes have we represented so far
    off_t outpos;         // how many bytes have been written to output
    off_t bakstart;       // position of start of active backref, or -1 if none
    off_t baklen;         // length of active backref, in BLOCKSZ blocks
    u64 numcell, numframe; // for statistics
    u64 datablocks, backblocks; // number of blocks of each, *not* cells
    u64 datacell, backcell; // number of cells, *not* blocks
    double start, lastprint; // for statistics
    int cellidx;          // index in cells[]
    int iovidx;           // index in iov[]
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

struct und_header {
    u32 magic;
    u32 version;
    u8 padding[BLOCKSZ - 2 * sizeof(u32)];
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

void und_header(struct undup *und)
{
    int r;
    struct und_header hd;

    memset(&hd, 0, sizeof(hd));
    hd.magic = htonl(UNDUP_MAGIC);
    hd.version = htonl(1);

    r = write(und->fd, &hd, sizeof(hd));
    if (r == -1)
        die("write: %s\n", strerror(errno));
    if (r != sizeof(hd))
        die("short write on header: wrote %d of %d\n", r, (int)sizeof(hd));
}

struct undup *new_undup_stream(int fd)
{
    struct undup *und = calloc(sizeof *und, 1);

    if (!und) return NULL;

    und->fd = fd;
    SHA256_Init(&und->streamctx);
    und->bakstart = -1;
    gettimeofday(&und->starttime, 0);
    und->start = und->lastprint = rtc();

    und_header(und);

    return und;
}

void und_trailer(struct undup *und)
{
    int r;
    u8 buf[BLOCKSZ] = { 0 };
    struct und_trailer *tr = (void *)buf;

    SHA256_Final(tr->hash, &und->streamctx);
    tr->len = htonl(und->logoff);
    tr->op = OP_TRAILER;
    r = write(und->fd, buf, BLOCKSZ);
    if (r == -1)
        die("write: %s\n", strerror(errno));
    if (r < BLOCKSZ)
        die("short write on trailer: wrote %d of %d\n", r, BLOCKSZ);
    und->curop = OP_TRAILER;
}

void und_trailer_finalize(struct undup *und)
{
    /* calling this function means that the stream was finalized twice, which
     * indicates a bug somewhere.
     */
    die("Botch: und_trailer_finalize called.\n");
}

#define NELEM(a) (sizeof(a)/sizeof((a)[0]))

void und_finalize(struct undup *und)
{
    debug("und_finalize curop %d\n", und->curop);
    if (und->curop >= 0 &&
        und->curop < NELEM(undfuncs) &&
        undfuncs[und->curop].finalize) {
        undfuncs[und->curop].finalize(und);
    }
    assert(und->bakstart == -1 && und->baklen == 0);
}

void und_flush_frame(struct undup *);

void und_flush(struct undup *und)
{
    und_finalize(und);
    und_flush_frame(und);
}

void end_undup_stream(struct undup *und)
{
    int r;
    struct timeval endtime;
    double t;

    debug("end undup len %lld\n", (long long)und->logoff);
    und_flush(und);
    und_trailer(und);

    r = close(und->fd);
    if (r != 0)
        die("close: %s\n", strerror(errno));

    gettimeofday(&endtime, 0);
    t = endtime.tv_sec - und->starttime.tv_sec +
        (endtime.tv_usec - und->starttime.tv_usec) / 1e6;

    if (o_verbose >= 1)
        fprintf(stderr, "%lld MiB -> %lld MiB (%.1f%% saved) in %.2f seconds (%.2f MiB/s) %lld cells %lld frames, %lld bak %lld dat\n",
                (long long)und->logoff / 1024 / 1024,
                (long long)und->outpos / 1024 / 1024,
                100 * (1 - und->outpos * 1. / und->logoff),
                t, und->logoff / 1024. / 1024 / t,
                (long long)und->numcell, (long long)und->numframe,
                (long long)und->backblocks, (long long)und->datablocks);
}

void und_check(struct undup *und)
{
    int i;
    off_t cellsz = 0, iovsz = 0;
    u32 len;

    debug("check: logoff %llx cells %d iovs %d\n",
          (long long)und->logoff, und->cellidx, und->iovidx);
    for (i=0; i<und->cellidx; i++) {

        if (und->cells[i][0] == OP_DATA) {
            struct data_cell *cell = (void *)und->cells[i];

            len = (ntohl(cell->len) & 0xffffff) * BLOCKSZ;
            cellsz += len;
            debug("check: data %d len %d total 0x%llx\n",
                  i, len, (long long)cellsz);
        } else if (und->cells[i][0] == OP_BACKREF) {
            struct backref_cell *cell = (void *)und->cells[i];
            off_t pos;

            pos = ntohll(cell->pos) & 0xffffffffffff;
            len = ntohl(cell->len);
            debug("check: back %d len %d @ %llx total 0x%llx\n",
                  i, len, (long long)pos, (long long)cellsz);
        }

    }
    for (i=0; i<und->iovidx+1; i++) {
        len = und->iov[i].iov_len;
        iovsz += len;
        debug("check: iov %-2d len %-6d @ %llx total 0x%llx\n",
              i, len, (long long)und->logoff, (long long)iovsz);
    }
    debug("cellsz = %lld iovsz = %lld\n", (long long)cellsz, (long long)iovsz);
    if (cellsz != iovsz)
        die("und_check: size mismatch at %llx\n", (long long)und->logoff);
}

void und_flush_frame(struct undup *und)
{
    int i, numiov;
    struct iovec iov[NUMCELL + 2];
    ssize_t r, expected;

    debug("flush cell %d iov %d iovlen %lld\n",
          und->cellidx, und->iovidx, (u64)und->iov[und->iovidx].iov_len);

    und_check(und);

    if (und->cellidx == 0 &&
        und->iovidx == 0 &&
        und->iov[0].iov_len == 0)
        return;

    /*
     * An incomplete metadata block should be padded with zero-length
     * op_data cells.
     */
    memset(und->cells + und->cellidx, 0, (NUMCELL - und->cellidx) * CELLSZ);
    for (i = und->cellidx; i < NUMCELL; i++)
        und->cells[i][0] = OP_DATA;

    for (i=0; i<und->iovidx + 1; i++)
        iov[i+1] = und->iov[i];
    iov[0].iov_base = und->cells;
    iov[0].iov_len = BLOCKSZ;
    numiov = und->iovidx + 2;

    expected = BLOCKSZ;
    for (i=0; i<und->iovidx+1; i++) {
        expected += und->iov[i].iov_len;
    }

    r = writev(und->fd, iov, numiov);
    if (r == -1)
        die("writev: %s\n", strerror(errno));
    if (r != expected)
        die("Short write on output (wrote %lld of %lld)\n", 
            (long long)r, (long long)expected);

    und->outpos += r;

    und->numframe++;

    /* reset for next frame */
    memset(und->cells, 0, sizeof(und->cells));
    for (i=0; i < und->iovidx; i++)
        free(und->iov[i].iov_base);
    memset(und->iov, 0, sizeof(und->iov));
    und->cellidx = 0;
    und->iovidx = 0;
    und->curop = -1;
}

void und_queue_cell(struct undup *und, void *cell, size_t cellsz)
{
    int i = und->cellidx++;

    assert(und->cellidx <= NUMCELL);

    if (cellsz != CELLSZ)
        die("Botch, %d != %d\n", (int)cellsz, CELLSZ);

    debug("queue cellidx=%d op=%d\n", i, ((u8 *)cell)[0]);

    und->numcell++;

    memcpy(und->cells[i], cell, cellsz);
    if (und->cellidx == NUMCELL) {
        und_flush_frame(und);
    } else if (und->iov[und->iovidx].iov_len) {
        und->iovidx++;
        assert(und->iovidx < NELEM(und->iov));
    }
}

void und_prep(struct undup *und, int opcode, void *buf, int len)
{
    assert(und->cellidx <= NUMCELL);

    SHA256_Update(&und->streamctx, buf, len);
    und->logoff += len;

    if (und->curop == opcode) {
        debug("und_prep: logoff %llx done op %d\n",
              (long long)und->logoff,  opcode);
        return;
    }

    und_finalize(und);

    und->curop = opcode;

    SHA256_Init(&und->blockctx);
}

void und_backref_cell(struct undup *und, off_t oldoff,
                      char *buf, int len, u8 *sha)
{
    und_prep(und, OP_BACKREF, buf, len);

    debug("BACK iovidx %d cellidx %d len %lld\n",
          und->iovidx, und->cellidx, (u64)und->iov[und->iovidx].iov_len);

    und->backblocks++;

    if (und->bakstart != -1 &&
        und->bakstart + und->baklen * BLOCKSZ == oldoff &&
        len % BLOCKSZ == 0) {
        /* extend existing backref */
        und->baklen += len / BLOCKSZ;
        SHA256_Update(&und->blockctx, buf, len);
    } else {
        if (und->bakstart != -1) {
            und_finalize(und);
            und->curop = OP_BACKREF;
         }
        und->bakstart = oldoff;
        und->baklen = len / BLOCKSZ;
    }
}

void und_backref_finalize(struct undup *und)
{
    struct backref_cell br;
    u8 sha[HASHSZ];

    debug("BACK finalize start %llx len %lld cellidx %d\n",
          (long long)und->bakstart, (long long)und->baklen, und->cellidx);

    memset(&br, 0, sizeof(br));
    br.pos = htonll(und->bakstart);
    if (br.op != 0)
        die("unpossible, start = %lld pos = 0x%llx op = %d\n",
            (long long)und->bakstart, (long long)br.pos, br.op);

    br.op = OP_BACKREF;
    br.len = htonl(und->baklen);

    SHA256_Final(sha, &und->blockctx);

    /* making a note here, this backref is recorded, huge success */
    und->bakstart = -1;
    und->baklen = 0;

    und->backcell++;

    und_queue_cell(und, &br, sizeof(br));
    debug("done finalizing backref start %llx len %d cellidx %d\n",
          ntohll(br.pos) & 0xffffffffffffff, ntohl(br.len),
          und->cellidx);
}

void und_data_cell(struct undup *und, char *buf, int len)
{
    int i, n;
    void *p;

    und_prep(und, OP_DATA, buf, len);
    SHA256_Update(&und->blockctx, buf, len);

    debug("DATA iovidx %d cellidx %d len %lld\n",
          und->iovidx, und->cellidx, (u64)und->iov[und->iovidx].iov_len);

    und->datablocks++;

    i = und->iovidx;
    n = und->iov[i].iov_len;
    p = realloc(und->iov[i].iov_base, n + len);
    memcpy((u8 *)p + n, buf, len);
    und->iov[i].iov_base = p;
    und->iov[i].iov_len = n + len;
}

void und_data_finalize(struct undup *und)
{
    struct data_cell da;
    u8 sha[HASHSZ];
    int len = und->iov[und->iovidx].iov_len;
    int numblock = len / BLOCKSZ + !!(len % BLOCKSZ);

    debug("DATA finalize iovidx %d cellidx %d len %d\n",
          und->iovidx, und->cellidx, len);

    da.len = htonl(numblock);
    if (da.op != 0)
        die("unpossible, numblock = %d len = %x op = %d\n",
            numblock, da.len, da.op);
    da.op = OP_DATA;
    SHA256_Final(sha, &und->blockctx);
    memcpy(da.hash, sha, sizeof(da.hash));

    und->datacell++;

    und_queue_cell(und, &da, sizeof(da));
}

int do_compress(int infd, int outfd);
int do_decompress(int infd, int outfd);

int main(int argc, char **argv)
{
    int c;
    int infd, outfd;

    while ((c = getopt(argc, argv, "dm:o:v")) != EOF) {
        switch (c) {
            case 'd':
                o_decompress = 1;
                break;
            case 'm':
                o_maxmem = strtol(optarg, 0, 0);
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

    if (o_decompress) {
        return do_decompress(infd, outfd);
    } else {
        return do_compress(infd, outfd);
    }
}

int do_compress(int infd, int outfd)
{
    int n;
    char *buf;
    struct undup *und;
    struct hashtable *table = new_hashtable(0, o_maxmem);
    int bufsz = BLOCKSZ;
    double t;
    int do_progress = 0;

    buf = malloc(bufsz);
    if (!buf) die("malloc(%d): %s\n", bufsz, strerror(errno));

    und = new_undup_stream(outfd);
    if (!und) die("new_undup_stream: %s\n", strerror(errno));

    if (isatty(2) && o_verbose == 1)
        do_progress = 1;

    while ((n = read(infd, buf, bufsz)) > 0) {
        u8 sha[HASHSZ];
        off_t oldoff;

        hash(buf, n, sha);
        oldoff = lookup_insert(table, sha, und->logoff);

        debug("%8llx read %d hash %02x%02x%02x%02x oldoff %llx\n",
              (long long)und->logoff, n,
              sha[0], sha[1], sha[2], sha[3], (long long)oldoff);

        if (oldoff != (off_t)-1 && n == BLOCKSZ) {
            und_backref_cell(und, oldoff, buf, n, sha);
        } else {
            und_data_cell(und, buf, n);
        }
        if (do_progress) {
            t = rtc();
            if (t > und->lastprint + 1) {
                u64 numblock = und->backblocks + und->datablocks;

                fprintf(stderr, "\r %lld MiB -> %lld MiB %.1f MiB/s %.1f%% backref %.1f%% data",
                        (long long)und->logoff / 1024 / 1024,
                        (long long)und->outpos / 1024 / 1024,
                        und->logoff / (t - und->start) / 1024 / 1024,
                        und->backblocks * 100. / numblock,
                        und->datablocks * 100. / numblock);
                und->lastprint = t;
            }
        }
    }
    if (n == -1)
        die("read: %s\n", strerror(errno));

    if (o_verbose >= 1) {
        t = rtc();
        u64 numblock = und->backblocks + und->datablocks;
        fprintf(stderr, "\n");
        fprintf(stderr, "Wrote %lld data blocks (%.1f%%) in %lld cells (%d blocks/cell), %lld MiB\n",
                (long long)und->datablocks,
                und->datablocks * 100. / numblock,
                und->datacell, (int)(und->datablocks / und->datacell),
                (und->datablocks * BLOCKSZ +
                 und->datacell * CELLSZ) / 1024 / 1024);
        fprintf(stderr, "      %lld back blocks (%.1f%%) in %lld cells (%d blocks/cell), %lld MiB\n",
                (long long)und->backblocks,
                und->backblocks * 100. / numblock,
                und->backcell, (int)(und->backblocks / und->backcell),
                und->backcell * CELLSZ / 1024 / 1024 );
        hash_stats(table, stderr);
    }

    end_undup_stream(und);

    return 0;
}

struct redup {
    int infd, outfd;
    off_t inpos;
    off_t framepos;
    off_t logpos;
    struct timeval starttime;
    SHA256_CTX streamctx;
};

struct redup_funcs {
    int (*do_frame)(struct redup *, void *);
};

int red_frame_data(struct redup *, void *);
int red_frame_backref(struct redup *, void *);
int red_frame_trailer(struct redup *, void *);

struct redup_funcs redup_func[] = {
    [OP_DATA] = { red_frame_data },
    [OP_BACKREF] = { red_frame_backref },
    [OP_TRAILER] = { red_frame_trailer },
};

struct redup *new_redup_stream(int infd, int outfd)
{
    struct redup *red = calloc(sizeof *red, 1);

    if (!red) die("Unable to malloc(%d)\n", (int)sizeof *red);

    red->infd = infd;
    red->outfd = outfd;

    SHA256_Init(&red->streamctx);
    gettimeofday(&red->starttime, 0);

    return red;
}

void end_redup_stream(struct redup *red)
{
    struct timeval endtime;
    double t;

    close(red->infd);
    if (close(red->outfd) == -1)
        die("close: %s\n", strerror(errno));
    gettimeofday(&endtime, 0);

    t = endtime.tv_sec - red->starttime.tv_sec +
        (endtime.tv_usec - red->starttime.tv_usec) / 1e6;

    if (o_verbose >= 1)
        fprintf(stderr, "%lld MiB -> %lld MiB in %.1f seconds (%.1f MiB/s)\n",
                (long long)red->inpos / 1024 / 1024,
                (long long)red->logpos / 1024 / 1024,
                t, red->logpos / 1024. / 1024 / t);
}

void red_header(struct redup *red, u8 *p)
{
    struct und_header *hd = (void *)p;

    debug("magic %x version %x\n", ntohl(hd->magic), ntohl(hd->version));

    if (ntohl(hd->magic) != UNDUP_MAGIC)
        die("Bad magic (got %x expected %x)\n", hd->magic, htonl(UNDUP_MAGIC));

    if (ntohl(hd->version) != 1)
        die("Unsupported version %d\n", ntohl(hd->version));
}

void red_frame(struct redup *red, u8 *buf)
{
    int i;
    int keepon = 1;

    assert(sizeof(redup_func) / sizeof(redup_func[0]) == 256);

    for (i=0; keepon && i<BLOCKSZ; i += CELLSZ) {
        debug("%6llx %6llx %6llx op %02x %02x %02x %02x %02x %02x %02x %02x\n",
              (long long)red->logpos, (long long)red->inpos,
              (long long)red->framepos + i,
              buf[i], buf[i+1], buf[i+2], buf[i+3],
              buf[i+4], buf[i+5], buf[i+6], buf[i+7]);

        if (!redup_func[buf[i]].do_frame)
            die("Invalid frame op 0x%02x\n", buf[i]);

        keepon = redup_func[buf[i]].do_frame(red, buf + i);
    }
}

int red_frame_data(struct redup *red, void *p)
{
    struct data_cell *dc = p;
    int numblk = ntohl(dc->len) & 0xffffff;
    char *buf = malloc(BLOCKSZ);
    int i, n;

    if (!buf) die("malloc(%d): %s\n", BLOCKSZ, strerror(errno));

    for (i=0; i<numblk; i++) {
        if ((n = read(red->infd, buf, BLOCKSZ)) != BLOCKSZ) {
            if (n == -1)
                die("read: %s\n", strerror(errno));
            else
                die("short read: wanted %d got %d (%d of %d blocks)\n",
                    BLOCKSZ, n, i, numblk);
        }
        red->inpos += n;

        SHA256_Update(&red->streamctx, buf, BLOCKSZ);

        if ((n = write(red->outfd, buf, BLOCKSZ)) != BLOCKSZ) {
            if (n == -1)
                die("write: %s\n", strerror(errno));
            else
                die("short write: wrote %d did %d (%d of %d blocks)\n",
                    BLOCKSZ, n, i, numblk);
        }
        debug("%6llx %06llx data %d %d/%d\n",
              (long long)red->logpos, (long long)red->inpos, n, i, numblk);
        red->logpos += n;
    }
    free(buf);

    return 1;
}

int red_frame_backref(struct redup *red, void *p)
{
    struct backref_cell *br = p;
    off_t oldpos = ntohll(br->pos) & 0xffffffffffff; // XXX lulzmask
    size_t numblk = ntohl(br->len);
    char *buf = malloc(BLOCKSZ);
    int i, n;

    if (!buf) die("malloc(%d): %s\n", BLOCKSZ, strerror(errno));

    if (lseek(red->outfd, oldpos, SEEK_SET) != oldpos)
        die("lseek(%lld): %s\n", (long long)oldpos, strerror(errno));

    debug("backref %d at %llx\n", (int)numblk, (long long)oldpos);

    for (i=0; i<numblk; i++) {
        if ((n = read(red->outfd, buf, BLOCKSZ)) != BLOCKSZ) {
            if (n == -1)
                die("read: %s\n", strerror(errno));
            else
                die("short read: wanted %d got %d (%d of %lld blocks)\n",
                    BLOCKSZ, n, i, (long long)numblk);
        }

        SHA256_Update(&red->streamctx, buf, BLOCKSZ);

        debug("write buf oldoff %llx newoff %llx\n",
              (long long)oldpos + i * BLOCKSZ, (long long)red->logpos);

        if ((n = pwrite(red->outfd, buf, BLOCKSZ, red->logpos)) != BLOCKSZ)
            die("pwrite(%lld): %s\n", (long long)red->logpos, strerror(errno));
        red->logpos += BLOCKSZ;
    }
    if (lseek(red->outfd, red->logpos, SEEK_SET) != red->logpos)
        die("lseek(%lld): %s\n", (long long)red->logpos, strerror(errno));
    free(buf);

    return 1;
}

char *format_sha(char *buf, u8 *hash)
{
    int i;

    for (i=0; i<HASHSZ; i++)
        sprintf(buf+i*2, "%02x", hash[i]);
    return buf;
}

int red_frame_trailer(struct redup *red, void *p)
{
    struct und_trailer *tr = p;
    off_t len;
    u8 sha[HASHSZ];
    char a[HASHSZ*2 + 1], b[HASHSZ*2 + 1];

    len = ntohll(tr->len) & 0xffffffffffff;

    SHA256_Final(sha, &red->streamctx);
    debug("len %llx hash %02x%02x%02x%02x\n",
          (long long)len, sha[0], sha[1], sha[2], sha[3]);
    if (memcmp(tr->hash, sha, HASHSZ) != 0)
        die("Hash mismatch! %s != %s\n",
            format_sha(a, sha), format_sha(b, tr->hash));
    return 0;
}

void hexdump(FILE *f, void *buf, int n)
{
    int i;
    u8 *p = buf;

    for (i=0; i<n; i++) {
        if (i % 16 == 0)
            fprintf(f, "%6x  ", i);
        fprintf(f, "%02x%s", p[i], i%16 == 15 ? "\n" : i%8 == 7 ? "  " : " ");
    }
    if (i % 16 != 0)
        fprintf(f, "\n");
}

int do_decompress(int infd, int outfd)
{
    struct redup *red;
    u8 *buf, *frame;
    int n;
    int bufsz = BLOCKSZ;

    buf = malloc(bufsz);
    frame = malloc(bufsz);
    if (!buf || !frame) die("malloc(%d): %s\n", bufsz, strerror(errno));

    red = new_redup_stream(infd, outfd);

    if ((n = read(infd, frame, bufsz)) == -1)
        die("read: %s\n", strerror(errno));
    red->inpos += n;

    red_header(red, frame);

    while ((n = read(infd, buf, bufsz)) > 0) {
        if (n < bufsz)
            die("Short read (expected %d got %d)\n", bufsz, n);
        red->framepos = red->inpos;
        red->inpos += n;
        if (o_verbose > 5)
            hexdump(stderr, buf, bufsz);
        red_frame(red, buf);
    }
    if (n == -1)
        die("read:%s\n", strerror(errno));

    end_redup_stream(red);

    return 0;
}
