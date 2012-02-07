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

void insert(struct hashtable *t, int idx, off_t off, u8 *sha)
{
    struct hashentry *e;

    e = malloc(sizeof *e);
    if (!e) {
        verbose("failed to malloc hashentry, off = %lld\n", (long long)off);
        return;
    }

    e->off = off;
    memcpy(e->hash, sha, HASHSZ);
    e->next = t->e[idx];
    t->e[idx] = e;

    debug("insert idx %d off %llx hash %02c%02c%02c%02c e %p next %p\n",
          idx, off, sha[0], sha[1], sha[2], sha[3], e, e->next);
}

off_t lookup_insert(struct hashtable *t, u8 *sha, off_t newoff)
{
    unsigned int idx = *(unsigned int *)sha % t->n;
    struct hashentry *e;

    debug("lookup idx %d e %p\n", idx, t->e[idx]);

    for (e = t->e[idx]; e; e = e->next) {
        if (!memcmp(e->hash, sha, HASHSZ))
            return e->off;
    }
    insert(t, idx, newoff, sha);
    return -1;
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
    off_t bakstart;       // position of start of active backref, or -1 if none
    off_t baklen;         // length of active backref, in BLOCKSZ blocks
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

    und_header(und);

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
    /* calling this function means that the stream was finalized twice, which
     * indicates a bug somewhere.
     */
    die("Botch: und_trailer_finalize called.\n");
}

void und_finalize(struct undup *und)
{
    if (undfuncs[und->curop].finalize) {
        undfuncs[und->curop].finalize(und);
    }
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

    debug("end undup len %lld\n", und->logoff);
    und_flush(und);
    und_trailer(und);

    r = close(und->fd);
    if (r != 0)
        die("close: %s\n", strerror(errno));
}

void und_flush_frame(struct undup *und)
{
    int i, numiov;
    struct iovec iov[NUMCELL + 1];
    ssize_t r, expected;

    debug("flush cell %d iov %d iovlen %lld\n",
          und->cellidx, und->iovidx, (u64)und->iov[und->iovidx].iov_len);

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
    numiov = und->iovidx + 1;

    expected = BLOCKSZ;
    for (i=0; i<und->iovidx; i++) {
        expected += und->iov[i].iov_len;
    }

    r = writev(und->fd, iov, numiov);
    if (r == -1)
        die("writev: %s\n", strerror(errno));
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

    debug("queue cellidx=%d\n", i);

    memcpy(und->cells[i], cell, cellsz);
    if (und->cellidx == NUMCELL) {
        und_flush_frame(und);
    }
}

void und_prep(struct undup *und, int opcode, void *buf, int len)
{
    assert(und->cellidx <= NUMCELL);

    SHA256_Update(&und->streamctx, buf, len);
    SHA256_Update(&und->blockctx, buf, len);
    und->logoff += len;

    if (und->curop == opcode)
        return;

    und_finalize(und);

    und->curop = opcode;

    SHA256_Init(&und->blockctx);
}

void und_backref_cell(struct undup *und, off_t oldoff,
                      char *buf, int len, u8 *sha)
{
    und_prep(und, OP_BACKREF, buf, len);

    if (und->bakstart != -1 &&
        und->bakstart + und->baklen * BLOCKSZ == oldoff &&
        len % BLOCKSZ == 0) {
        /* extend existing backref */
        und->baklen += len / BLOCKSZ;
    } else {
        if (und->bakstart != -1)
            und_finalize(und);
        und->bakstart = oldoff;
        und->baklen = len / BLOCKSZ;
    }
}

void und_backref_finalize(struct undup *und)
{
    struct backref_cell br;
    u8 sha[HASHSZ];

    debug("BACK finalize start %lld\n", und->bakstart);

    br.pos = htonll(und->bakstart);
    if (br.op != 0)
        die("unpossible, start = %lld pos = 0x%llx op = %d\n",
            und->bakstart, br.pos, br.op);

    br.op = OP_BACKREF;
    br.len = htonl(und->baklen);

    SHA256_Final(sha, &und->blockctx);
    und_queue_cell(und, &br, sizeof(br));
}

void und_data_cell(struct undup *und, char *buf, int len)
{
    int i, n;
    void *p;

    und_prep(und, OP_DATA, buf, len);

    debug("DATA iovidx %d cellidx %d len %lld\n",
          und->iovidx, und->cellidx, (u64)und->iov[und->iovidx].iov_len);

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
    und_queue_cell(und, &da, sizeof(da));
    und->iovidx++;
}

int do_compress(int infd, int outfd);
int do_decompress(int infd, int outfd);

int main(int argc, char **argv)
{
    int c;
    int infd, outfd;

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
    struct hashtable *table = new_hashtable(0);
    int bufsz = BLOCKSZ;

    buf = malloc(bufsz);
    if (!buf) die("malloc(%d): %s\n", bufsz, strerror(errno));

    und = new_undup_stream(outfd);
    if (!und) die("new_undup_stream: %s\n", strerror(errno));

    while ((n = read(infd, buf, bufsz)) > 0) {
        u8 sha[HASHSZ];
        off_t oldoff;

        hash(buf, n, sha);
        oldoff = lookup_insert(table, sha, und->logoff);

        debug("%8llx read %d hash %02x%02x%02x%02x oldoff %llx\n",
              und->logoff, n, sha[0], sha[1], sha[2], sha[3], oldoff);

        if (oldoff != (off_t)-1 && n == BLOCKSZ) {
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

struct redup {
    int infd, outfd;
    off_t logpos;
    SHA256_CTX streamctx;
};

struct redup_funcs {
    void (*do_frame)(struct redup *, void *);
};

void red_frame_data(struct redup *, void *);
void red_frame_backref(struct redup *, void *);
void red_frame_trailer(struct redup *, void *);

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

    return red;
}

void end_redup_stream(struct redup *red)
{
    close(red->infd);
    if (close(red->outfd) == -1)
        die("close: %s\n", strerror(errno));
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

    assert(sizeof(redup_func) / sizeof(redup_func[0]) == 256);

    for (i=0; i<BLOCKSZ; i += CELLSZ) {
        debug("%6x op %02x\n", red->logpos, buf[i]);

        if (!redup_func[buf[i]].do_frame)
            die("Invalid frame op 0x%02x\n", buf[i]);

        redup_func[buf[i]].do_frame(red, buf + i);
    }
}

void red_frame_data(struct redup *red, void *p)
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

        SHA256_Update(&red->streamctx, buf, BLOCKSZ);

        if ((n = write(red->outfd, buf, BLOCKSZ)) != BLOCKSZ) {
            if (n == -1)
                die("write: %s\n", strerror(errno));
            else
                die("short write: wrote %d did %d (%d of %d blocks)\n",
                    BLOCKSZ, n, i, numblk);
        }
        debug("%6llx data %d\n", red->logpos, n);
        red->logpos += n;
    }
    free(buf);
}

void red_frame_backref(struct redup *red, void *p)
{
    struct backref_cell *br = p;
    off_t oldpos = ntohll(br->pos) & 0xffffffffffff; // XXX lulzmask
    size_t numblk = ntohl(br->len);
    char *buf = malloc(BLOCKSZ);
    int i, n;

    if (!buf) die("malloc(%d): %s\n", BLOCKSZ, strerror(errno));

    if (lseek(red->outfd, oldpos, SEEK_SET) != oldpos)
        die("lseek(%lld): %s\n", (long long)oldpos, strerror(errno));

    debug("backref %d at %llx\n", numblk, oldpos);

    for (i=0; i<numblk; i++) {
        if ((n = read(red->outfd, buf, BLOCKSZ)) != BLOCKSZ) {
            if (n == -1)
                die("read: %s\n", strerror(errno));
            else
                die("short read: wanted %d got %d (%d of %d blocks)\n",
                    BLOCKSZ, n, i, numblk);
        }

        SHA256_Update(&red->streamctx, buf, BLOCKSZ);

        debug("write buf oldoff %llx newoff %llx\n",
              oldpos + i * BLOCKSZ, red->logpos);

        if ((n = pwrite(red->outfd, buf, BLOCKSZ, red->logpos)) != BLOCKSZ)
            die("pwrite(%lld): %s\n", (long long)red->logpos, strerror(errno));
        red->logpos += BLOCKSZ;
    }
    if (lseek(red->outfd, red->logpos, SEEK_SET) != red->logpos)
        die("lseek(%lld): %s\n", (long long)red->logpos, strerror(errno));

}

void red_frame_trailer(struct redup *red, void *p)
{
    struct und_trailer *tr = p;
    off_t len;
    u8 sha[HASHSZ];

    len = ntohll(tr->len) & 0xffffffffffff;

    SHA256_Final(sha, &red->streamctx);
    debug("len %llx hash %02x%02x%02x%02x\n",
          len, sha[0], sha[1], sha[2], sha[3]);
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

    red_header(red, frame);

    while ((n = read(infd, buf, bufsz)) > 0) {
        if (n < bufsz)
            die("Short read (expected %d got %d)\n", bufsz, n);
        red_frame(red, buf);
    }
    if (n == -1)
        die("read:%s\n", strerror(errno));

    end_redup_stream(red);

    return 0;
}
