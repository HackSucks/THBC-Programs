/*
 * LinuxSwitch - UnshackleOS root switcher for Tizen TVs
 *
 * Implements SWITCHER.md (chroot-based, no PID 1 replacement, no pivot_root,
 * nothing persistent written) and adds support for fetching unshackle.squashfs
 * over the network (plain HTTP) in addition to a USB stick.
 *
 * Build (static, via Zig; no libc dependencies on the TV):
 *   ARMv7 32-bit TV : zig cc -target arm-linux-musleabihf -Os -static -o LinuxSwitch LinuxSwitch.c
 *   AArch64 TV      : zig cc -target aarch64-linux-musl   -Os -static -o LinuxSwitch LinuxSwitch.c
 *   (check `uname -m` on the TV; add -mcpu=cortex_a9 etc. if you hit SIGILL)
 *
 * Usage (as root on the TV):
 *   LinuxSwitch                         USB stick: unshackle.squashfs, or unshackle.url
 *   LinuxSwitch --url http://h:8000/unshackle.squashfs
 *   LinuxSwitch --scan                  find a server on the LAN (:8000/unshackle.squashfs) and pick it
 *   LinuxSwitch --download-only --url ... --cache /tmp/mnt   (stage the image, then exit)
 *   LinuxSwitch --teardown [--reboot]   undo mounts/processes without rebooting
 *   LinuxSwitch --help
 *
 * Image source priority:
 *   1. --url                         (network)
 *   2. unshackle.squashfs on stick   (local)
 *   3. unshackle.url on stick        (first line = http:// URL)
 *   --prefer-net swaps 2 and 3.
 *
 * Storage safety: LinuxSwitch never opens mmcblk or mtd nodes, only mounts USB-backed
 * sd devices (verified through sysfs), only writes to tmpfs or the USB stick, and hides
 * every non-USB block device and mtd node from the chroot. This guards against accidents
 * (dd, mkfs, automounters); it is not a sandbox against a deliberately hostile root.
 *
 * Network notes: the TV kernel only has squashfs/vfat/msdos/fuse/vdfs, so there
 * is no NFS/CIFS/NBD. The image is therefore downloaded (resumable, Range
 * requests) to a cache file and loop-mounted from there. Cache location:
 *   --cache DIR  >  the USB stick (remounted rw)  >  RAM (/tmp, size-gated).
 * Only http:// is supported (no TLS library in a static build). Put the image on
 * a LAN server, or use a TLS-terminating proxy. An optional <url>.sha256 file
 * (or --sha256) is verified when present. unshackle.conf is also fetched from
 * the same directory as the image if the stick has none.
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <ctype.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/loop.h>

#define VERSION   "1.0"
#define W         "/tmp/unshackle"
#define NR        W "/newroot"
#define USBDIR    W "/usb"
#define NETDIR    W "/net"
#define RUNDIR    "/run/unshackle"
#define LOGFILE   W "/switcher.log"
#define IMGNAME   "unshackle.squashfs"
#define API_URL   "http://127.0.0.1:7777/api/state"
#define MB        (1024LL * 1024LL)

/* ------------------------------------------------------------------ options */

static struct {
    const char *url;          /* --url */
    const char *sha;          /* --sha256 */
    const char *cache;        /* --cache */
    const char *agent;        /* --agent */
    const char *smack;        /* --smack */
    const char *logdir;       /* --logdir */
    const char *extra[16];    /* --kill */
    int n_extra;
    int prefer_net, kill_streaming, no_reboot, download_only, menu, unsafe_paths, scan;
    int teardown, reboot_after;
    long min_mem;             /* MB */
    int wait_sec;             /* -1 = auto */
    int timeout;              /* health gate seconds */
} O = { .min_mem = 450, .wait_sec = -1, .timeout = 45 };

/* ------------------------------------------------------------------ logging */

static FILE *g_log;

static void say(const char *fmt, ...)
{
    char b[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    fprintf(stderr, "[LinuxSwitch] %s\n", b);
    if (g_log) { fprintf(g_log, "%s\n", b); fflush(g_log); }
}

/* ------------------------------------------------------------------ helpers */

static int exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

static void mkdir_p(const char *path, mode_t mode)
{
    char t[512];
    snprintf(t, sizeof t, "%s", path);
    for (char *p = t + 1; *p; p++)
        if (*p == '/') { *p = 0; mkdir(t, mode); *p = '/'; }
    mkdir(t, mode);
}

static int slurp(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return (int)n;
}

static int copy_file(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out < 0) { close(in); return -1; }
    char b[8192];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, b, sizeof b)) > 0)
        if (write(out, b, n) != n) { rc = -1; break; }
    close(in);
    close(out);
    return rc;
}

static void trim(char *s)
{
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    char *b = s;
    while (*b && isspace((unsigned char)*b)) b++;
    if (b != s) memmove(s, b, strlen(b) + 1);
}

static long mem_avail_mb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char l[256];
    long kb = -1;
    while (fgets(l, sizeof l, f))
        if (sscanf(l, "MemAvailable: %ld kB", &kb) == 1) break;
    fclose(f);
    return kb < 0 ? -1 : kb / 1024;
}

static int do_mount(const char *src, const char *tgt, const char *type,
                    unsigned long flags, const char *data)
{
    if (mount(src, tgt, type, flags, data) != 0) {
        say("mount %s -> %s (%s) failed: %s", src ? src : "none", tgt,
            type ? type : "bind", strerror(errno));
        return -1;
    }
    return 0;
}

static void sync_reboot(void)
{
    say("rebooting");
    sync();
    reboot(RB_AUTOBOOT);
    sleep(5);
}

/* ------------------------------------------------------------------- SHA-256 */

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha_t;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(sha_t *s, const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha_init(sha_t *s)
{
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->len = 0; s->n = 0;
}

static void sha_update(sha_t *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    s->len += len;
    while (len) {
        size_t k = 64 - s->n;
        if (k > len) k = len;
        memcpy(s->buf + s->n, p, k);
        s->n += k; p += k; len -= k;
        if (s->n == 64) { sha_block(s, s->buf); s->n = 0; }
    }
}

static void sha_hex(sha_t *s, char out[65])
{
    uint64_t bits = s->len * 8;
    uint8_t pad = 0x80;
    sha_update(s, &pad, 1);
    pad = 0;
    while (s->n != 56) sha_update(s, &pad, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(s, lb, 8);
    for (int i = 0; i < 8; i++) snprintf(out + 8 * i, 9, "%08x", s->h[i]);
}

static int sha_file(const char *path, char out[65])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    static uint8_t buf[1 << 20];
    sha_t s;
    sha_init(&s);
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) sha_update(&s, buf, (size_t)n);
    close(fd);
    if (n < 0) return -1;
    sha_hex(&s, out);
    return 0;
}

/* Extract the first 64-hex-digit token from "<hex>  filename" text. */
static int sha_parse(const char *text, char out[65])
{
    while (*text && isspace((unsigned char)*text)) text++;
    for (int i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)text[i])) return -1;
        out[i] = (char)tolower((unsigned char)text[i]);
    }
    out[64] = 0;
    return 0;
}

/* Verify file against expected hex; returns 0 on match. */
static int sha_verify(const char *path, const char *expect_text)
{
    char want[65], got[65];
    if (sha_parse(expect_text, want) != 0) { say("bad SHA-256 string"); return -1; }
    say("verifying SHA-256 of %s ...", path);
    if (sha_file(path, got) != 0) { say("cannot read %s", path); return -1; }
    if (strcmp(want, got) != 0) { say("SHA-256 MISMATCH\n  want %s\n  got  %s", want, got); return -1; }
    say("SHA-256 OK");
    return 0;
}

/* --------------------------------------------------------------- HTTP client */

typedef struct { int fd; unsigned char b[16384]; size_t p, n; } rd_t;

typedef struct {
    int status;
    long long clen;            /* Content-Length, -1 unknown */
    long long cr_start, cr_total;
    int chunked;
    char loc[2048];
    rd_t r;
} resp_t;

static int rd_fill(rd_t *r)
{
    ssize_t k;
    do k = recv(r->fd, r->b, sizeof r->b, 0); while (k < 0 && errno == EINTR);
    if (k <= 0) return -1;
    r->p = 0; r->n = (size_t)k;
    return 0;
}

static int rd_getc(rd_t *r)
{
    if (r->p >= r->n && rd_fill(r) < 0) return -1;
    return r->b[r->p++];
}

static int rd_line(rd_t *r, char *o, size_t m)
{
    size_t i = 0;
    int c;
    while ((c = rd_getc(r)) >= 0) {
        if (c == '\n') break;
        if (c != '\r' && i + 1 < m) o[i++] = (char)c;
    }
    if (c < 0 && i == 0) return -1;
    o[i] = 0;
    return (int)i;
}

static ssize_t rd_some(rd_t *r, void *d, size_t want)
{
    if (r->p >= r->n && rd_fill(r) < 0) return 0;
    size_t k = r->n - r->p;
    if (k > want) k = want;
    memcpy(d, r->b + r->p, k);
    r->p += k;
    return (ssize_t)k;
}

/* returns 0 ok, -1 error, -2 https */
static int parse_url(const char *u, char *host, size_t hs, char *port, size_t ps,
                     char *path, size_t pas)
{
    if (!strncasecmp(u, "https://", 8)) return -2;
    if (strncasecmp(u, "http://", 7)) return -1;
    u += 7;
    const char *slash = strchr(u, '/');
    size_t alen = slash ? (size_t)(slash - u) : strlen(u);
    char auth[256];
    if (alen == 0 || alen >= sizeof auth || alen >= hs) return -1;
    memcpy(auth, u, alen); auth[alen] = 0;
    snprintf(path, pas, "%s", slash ? slash : "/");
    snprintf(port, ps, "80");
    char *colon = strrchr(auth, ':');
    if (colon && !strchr(colon, ']')) { *colon = 0; snprintf(port, ps, "%s", colon + 1); }
    snprintf(host, hs, "%s", auth);
    return host[0] ? 0 : -1;
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res, *a;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    int gi = getaddrinfo(host, port, &hints, &res);
    if (gi != 0) { say("resolve %s failed: %s", host, gai_strerror(gi)); return -1; }
    int fd = -1;
    for (a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = { .tv_sec = 20 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) say("connect %s:%s failed", host, port);
    return fd;
}

static int send_all(int fd, const char *b, size_t n)
{
    while (n) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        b += w; n -= (size_t)w;
    }
    return 0;
}

/* Issues a request (follows up to 5 redirects). Returns HTTP status or -1.
 * On success rs->r.fd stays open; caller must close it. */
static int http_request(const char *url0, const char *method, long long from, resp_t *rs)
{
    char url[2048];
    snprintf(url, sizeof url, "%s", url0);
    for (int hop = 0; hop < 6; hop++) {
        char host[256], port[8], path[1900];
        int pr = parse_url(url, host, sizeof host, port, sizeof port, path, sizeof path);
        if (pr == -2) { say("https:// is not supported (static build has no TLS). Use http://"); return -1; }
        if (pr < 0) { say("bad URL: %s", url); return -1; }
        int fd = tcp_connect(host, port);
        if (fd < 0) return -1;

        char req[2600];
        int n = snprintf(req, sizeof req,
                         "%s %s HTTP/1.1\r\nHost: %s%s%s\r\nUser-Agent: LinuxSwitch/" VERSION
                         "\r\nAccept: */*\r\nConnection: close\r\n",
                         method, path, host, strcmp(port, "80") ? ":" : "",
                         strcmp(port, "80") ? port : "");
        if (from > 0)
            n += snprintf(req + n, sizeof req - (size_t)n, "Range: bytes=%lld-\r\n", from);
        n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");
        if (send_all(fd, req, (size_t)n) != 0) { close(fd); return -1; }

        memset(rs, 0, sizeof *rs);
        rs->r.fd = fd; rs->clen = -1; rs->cr_start = -1; rs->cr_total = -1;
        char line[2200];
        if (rd_line(&rs->r, line, sizeof line) < 0 || sscanf(line, "HTTP/%*s %d", &rs->status) != 1) {
            close(fd); say("bad HTTP response from %s", host); return -1;
        }
        while (rd_line(&rs->r, line, sizeof line) > 0) {
            if (!strncasecmp(line, "Content-Length:", 15)) rs->clen = atoll(line + 15);
            else if (!strncasecmp(line, "Transfer-Encoding:", 18) && strcasestr(line, "chunked")) rs->chunked = 1;
            else if (!strncasecmp(line, "Content-Range:", 14)) {
                long long a = -1, t = -1;
                if (sscanf(line + 14, " bytes %lld-%*d/%lld", &a, &t) >= 1) { rs->cr_start = a; rs->cr_total = t; }
            } else if (!strncasecmp(line, "Location:", 9)) {
                snprintf(rs->loc, sizeof rs->loc, "%s", line + 9);
                trim(rs->loc);
            }
        }
        int st = rs->status;
        if ((st == 301 || st == 302 || st == 303 || st == 307 || st == 308) && rs->loc[0]) {
            close(fd);
            if (!strncasecmp(rs->loc, "http", 4)) snprintf(url, sizeof url, "%s", rs->loc);
            else if (rs->loc[0] == '/')
                snprintf(url, sizeof url, "http://%s:%s%s", host, port, rs->loc);
            else { say("unsupported redirect: %s", rs->loc); return -1; }
            continue;
        }
        return st;
    }
    say("too many redirects");
    return -1;
}

typedef int (*sink_fn)(void *, const void *, size_t);

static int body_copy(resp_t *rs, long long n, sink_fn f, void *c)
{
    unsigned char tmp[16384];
    while (n != 0) {
        size_t want = sizeof tmp;
        if (n > 0 && (long long)want > n) want = (size_t)n;
        ssize_t k = rd_some(&rs->r, tmp, want);
        if (k <= 0) return n < 0 ? 0 : -1;       /* EOF is fine only if length unknown */
        if (f(c, tmp, (size_t)k)) return -1;
        if (n > 0) n -= k;
    }
    return 0;
}

static int http_body(resp_t *rs, sink_fn f, void *c)
{
    if (!rs->chunked) return body_copy(rs, rs->clen, f, c);
    char line[64];
    for (;;) {
        if (rd_line(&rs->r, line, sizeof line) < 0) return -1;
        long long sz = strtoll(line, NULL, 16);
        if (sz == 0) { while (rd_line(&rs->r, line, sizeof line) > 0) {} return 0; }
        if (body_copy(rs, sz, f, c) != 0) return -1;
        if (rd_line(&rs->r, line, sizeof line) < 0) return -1;
    }
}

typedef struct { char *b; size_t cap, n; } mem_t;

static int mem_sink(void *c, const void *d, size_t n)
{
    mem_t *m = c;
    if (m->n + n >= m->cap) return -1;
    memcpy(m->b + m->n, d, n);
    m->n += n; m->b[m->n] = 0;
    return 0;
}

/* GET a small text resource. Returns length, -2 for 404, -1 otherwise. */
static int fetch_small(const char *url, char *buf, size_t cap)
{
    static resp_t rs;
    int st = http_request(url, "GET", 0, &rs);
    if (st < 0) return -1;
    if (st != 200) { close(rs.r.fd); return st == 404 ? -2 : -1; }
    mem_t m = { buf, cap, 0 };
    buf[0] = 0;
    int rc = http_body(&rs, mem_sink, &m);
    close(rs.r.fd);
    return rc ? -1 : (int)m.n;
}

typedef struct { int fd; long long done, total; int lastpct; } dl_t;

static int dl_sink(void *c, const void *d, size_t n)
{
    dl_t *s = c;
    const char *p = d;
    size_t o = 0;
    while (o < n) {
        ssize_t w = write(s->fd, p + o, n - o);
        if (w < 0) { if (errno == EINTR) continue; say("write error: %s", strerror(errno)); return -1; }
        o += (size_t)w;
    }
    s->done += (long long)n;
    if (s->total > 0) {
        int pct = (int)(s->done * 100 / s->total);
        if (pct >= s->lastpct + 5) {
            s->lastpct = pct;
            say("download %d%% (%lld / %lld MB)", pct, s->done / MB, s->total / MB);
        }
    } else if (s->done / (50 * MB) > s->lastpct) {
        s->lastpct = (int)(s->done / (50 * MB));
        say("downloaded %lld MB", s->done / MB);
    }
    return 0;
}

/* Download (resumable) + verify + cache. dir is the cache directory.
 * expect_sha may be NULL. Result path in out. Returns 0 on success. */
static int fetch_image(const char *url, const char *dir, const char *expect_sha,
                       int ram, char *out, size_t osz)
{
    static resp_t rs;
    char fin[600], part[620];
    snprintf(fin, sizeof fin, "%s/" IMGNAME, dir);
    snprintf(part, sizeof part, "%s.part", fin);
    mkdir_p(dir, 0755);

    /* Learn the size (best effort). */
    long long total = -1;
    int st = http_request(url, "HEAD", 0, &rs);
    if (st >= 0) { if (st == 200) total = rs.clen; close(rs.r.fd); }
    else say("HEAD failed; will try GET anyway");

    /* Cache hit? */
    struct stat sb;
    if (stat(fin, &sb) == 0) {
        int hit = 0;
        if (expect_sha) hit = (sha_verify(fin, expect_sha) == 0);
        else if (total > 0 && sb.st_size == total) hit = 1;
        if (hit) {
            say("using cached image %s", fin);
            snprintf(out, osz, "%s", fin);
            return 0;
        }
        say("cached image is stale/corrupt, removing");
        unlink(fin);
    }

    /* Space / RAM checks. */
    long long have0 = (stat(part, &sb) == 0) ? sb.st_size : 0;
    if (ram) {
        long avail = mem_avail_mb();
        if (total <= 0) { say("RAM cache needs a known Content-Length; refusing"); return -1; }
        if (avail >= 0 && avail < total / MB + O.min_mem) {
            say("image (%lld MB) + %ld MB reserve does not fit in %ld MB free RAM; "
                "use --cache on a USB stick", total / MB, O.min_mem, avail);
            return -1;
        }
    }
    struct statvfs sv;
    if (total > 0 && statvfs(dir, &sv) == 0) {
        long long freeb = (long long)sv.f_bavail * (long long)sv.f_frsize;
        if (freeb < total - have0) {
            say("not enough space in %s: need %lld MB, have %lld MB", dir,
                (total - have0) / MB, freeb / MB);
            return -1;
        }
    }

    int done = 0;
    for (int att = 0; att < 8 && !done; att++) {
        long long have = (stat(part, &sb) == 0) ? sb.st_size : 0;
        if (total > 0 && have >= total) { (void)!truncate(part, 0); have = 0; }
        say("GET %s%s (attempt %d)", url, have ? " [resume]" : "", att + 1);
        st = http_request(url, "GET", have, &rs);
        if (st < 0) { sleep(2 * (unsigned)(att + 1)); continue; }
        if (st == 416) { close(rs.r.fd); (void)!truncate(part, 0); continue; }
        if (st != 200 && st != 206) {
            close(rs.r.fd);
            say("server answered HTTP %d", st);
            if (st >= 400 && st < 500) return -1;
            sleep(2 * (unsigned)(att + 1));
            continue;
        }
        if (st == 206 && rs.cr_start != have) { close(rs.r.fd); (void)!truncate(part, 0); continue; }
        if (st == 200) { have = 0; total = rs.clen; }
        else if (rs.cr_total > 0) total = rs.cr_total;

        int fd = open(part, O_WRONLY | O_CREAT | O_CLOEXEC | (st == 200 ? O_TRUNC : 0), 0644);
        if (fd < 0) { close(rs.r.fd); say("cannot open %s: %s", part, strerror(errno)); return -1; }
        if (st == 206) lseek(fd, 0, SEEK_END);
        dl_t d = { fd, have, total, (int)(total > 0 ? have * 100 / total : 0) };
        int rc = http_body(&rs, dl_sink, &d);
        close(rs.r.fd);
        fsync(fd);
        close(fd);
        if (rc == 0 && (total <= 0 || (stat(part, &sb) == 0 && sb.st_size == total))) done = 1;
        else say("transfer interrupted, will resume");
    }
    if (!done) { say("download failed"); return -1; }

    if (expect_sha && sha_verify(part, expect_sha) != 0) { unlink(part); return -1; }
    if (rename(part, fin) != 0) { say("rename failed: %s", strerror(errno)); return -1; }
    sync();
    say("image ready: %s", fin);
    snprintf(out, osz, "%s", fin);
    return 0;
}

/* ---------------------------------------------------------------- USB stick */

static int g_usb_mounted, g_usb_rw;
static char g_usb_dev[64];

/* ---- eMMC safety helpers ------------------------------------------------ */

#define TMPFS_MAGIC_ 0x01021994

/* True if writing to `path` is allowed: it must live on tmpfs, or inside the
 * mounted USB stick. Works for paths that do not exist yet (checks the nearest
 * existing parent), so nothing is created on an unsafe filesystem first. */
static int write_ok(const char *path)
{
    if (O.unsafe_paths) return 1;
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s", path);
    for (;;) {
        char real[PATH_MAX];
        if (realpath(p, real)) {
            size_t ul = strlen(USBDIR);
            if (!strncmp(real, USBDIR, ul) && (real[ul] == '/' || real[ul] == 0))
                return g_usb_mounted;
            struct statfs sf;
            return statfs(real, &sf) == 0 && (unsigned long)sf.f_type == TMPFS_MAGIC_;
        }
        char *sl = strrchr(p, '/');
        if (!sl) return 0;
        if (sl == p) { if (p[1] == 0) return 0; p[1] = 0; continue; }
        *sl = 0;
    }
}

/* True only if block device `name` (e.g. "sda1") hangs off a USB bus. */
static int usb_backed(const char *name)
{
    char p[128], real[PATH_MAX];
    snprintf(p, sizeof p, "/sys/class/block/%s", name);
    if (!realpath(p, real)) return 0;
    return strstr(real, "/usb") != NULL;
}

/* Hide every block device except USB sd* (and every mtd node) from the chroot by
 * bind-mounting /dev/null over it. Must run after NR/dev is made private, or the
 * masks would propagate back to Tizen's real /dev. */
static int mask_devices(void)
{
    DIR *d = opendir(NR "/dev");
    if (!d) { say("cannot open %s/dev: %s", NR, strerror(errno)); return -1; }
    struct dirent *e;
    int masked = 0, rc = 0;
    while ((e = readdir(d))) {
        char path[300];
        struct stat st;
        snprintf(path, sizeof path, NR "/dev/%s", e->d_name);
        if (lstat(path, &st) != 0) continue;
        int hide = 0;
        if (S_ISBLK(st.st_mode))
            hide = !(!strncmp(e->d_name, "sd", 2) && usb_backed(e->d_name));
        else if (S_ISCHR(st.st_mode) && !strncmp(e->d_name, "mtd", 3))
            hide = 1;
        if (!hide) continue;
        if (mount("/dev/null", path, NULL, MS_BIND, NULL) != 0) {
            say("FAILED to mask %s: %s", path, strerror(errno));
            rc = -1;
        } else masked++;
    }
    closedir(d);
    say("storage safety: masked %d block/mtd device node(s) in the chroot", masked);
    return rc;
}

static int usb_try(const char *dev)
{
    if (mount(dev, USBDIR, "vfat", MS_RDONLY, NULL) != 0) return 0;
    if (exists(USBDIR "/" IMGNAME) || exists(USBDIR "/unshackle.url") ||
        exists(USBDIR "/unshackle.conf")) {
        snprintf(g_usb_dev, sizeof g_usb_dev, "%s", dev);
        return 1;
    }
    umount(USBDIR);
    return 0;
}

static int find_usb(int wait_sec)
{
    for (int t = 0; t <= wait_sec; t++) {
        for (char c = 'a'; c <= 'z'; c++) {
            char dev[32];
            char nm[8];
            snprintf(nm, sizeof nm, "sd%c1", c);
            snprintf(dev, sizeof dev, "/dev/%s", nm);
            if (exists(dev) && usb_backed(nm) && usb_try(dev)) return 1;
            snprintf(nm, sizeof nm, "sd%c", c);
            snprintf(dev, sizeof dev, "/dev/%s", nm);
            if (exists(dev) && usb_backed(nm) && usb_try(dev)) return 1;
        }
        if (t < wait_sec) sleep(1);
    }
    return 0;
}

static int usb_make_rw(void)
{
    if (!g_usb_mounted) return -1;
    if (g_usb_rw) return 0;
    if (mount(g_usb_dev, USBDIR, "vfat", MS_REMOUNT, NULL) != 0) {
        say("cannot remount stick read-write: %s", strerror(errno));
        return -1;
    }
    g_usb_rw = 1;
    return 0;
}

/* ---------------------------------------------------------- process control */

static const char *const KEEP[] = {
    "systemd", "stability-monitor", "sp-kpi", "enlightenment", "avocd", "tzdaemon",
    "tvs-daemon", "tvs-lite", "tvctx-manager", "pulseaudio", "connmand", "wpa_supplicant",
    "net-config", "buxton2d", "cynara", "security-manager", "amd", "launchpad-process-pool",
    "kfactoryd", "fconfigd", "muse-server", "media-server", "deviced", "boot-helper-dyboost-tv",
    "resourced", "reclaimd", "storaged", "key-manager", "bt-service", "hdmicec-service",
    "sensord", NULL
};

static const char *const KILL_BASE[] = {
    "hbbtv", "acr-service-app", "com.samsung.tv.cis", "slive", "pisa", "content-tiles",
    "ContentServiceManager", "canal", "spotifyd", "dmr_service_app", "airplay", NULL
};

static const char *const KILL_STREAM[] = {
    "org.tizen.netflix-app", "com.samsung.tv.cobalt", NULL
};

static int is_keep(const char *base, const char *comm)
{
    for (int i = 0; KEEP[i]; i++) {
        if (!strcmp(base, KEEP[i])) return 1;
        if (comm[0]) {
            if (strlen(comm) < 15 ? !strcmp(comm, KEEP[i]) : !strncmp(comm, KEEP[i], 15)) return 1;
        }
    }
    return 0;
}

/* Signals processes whose cmdline contains any pattern (pkill -f semantics),
 * but never keep-list processes, PID 1, or ourselves. If force_name != NULL,
 * matches basename exactly and ignores the keep list (used for enlightenment). */
static int signal_procs(const char *const *pats, const char *force_name, int sig)
{
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    int hit = 0;
    pid_t self = getpid(), par = getppid();
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 1 || pid == self || pid == par) continue;
        char p[64], cmd[4096], comm[64] = "";
        snprintf(p, sizeof p, "/proc/%d/cmdline", pid);
        int n = slurp(p, cmd, sizeof cmd);
        if (n <= 0) continue;                             /* kernel thread / gone */
        for (int i = 0; i < n; i++) if (cmd[i] == 0) cmd[i] = ' ';
        if (strstr(cmd, "LinuxSwitch")) continue;
        snprintf(p, sizeof p, "/proc/%d/comm", pid);
        slurp(p, comm, sizeof comm);
        trim(comm);
        char first[4096];
        snprintf(first, sizeof first, "%s", cmd);
        char *sp = strchr(first, ' ');
        if (sp) *sp = 0;
        const char *base = strrchr(first, '/');
        base = base ? base + 1 : first;

        int match = 0;
        if (force_name) match = !strcmp(base, force_name);
        else {
            if (is_keep(base, comm)) continue;
            for (int i = 0; pats[i]; i++) if (strstr(cmd, pats[i])) { match = 1; break; }
        }
        if (match) { kill(pid, sig); hit++; }
    }
    closedir(d);
    return hit;
}

static void free_ram(void)
{
    const char *all[48];
    int n = 0;
    for (int i = 0; KILL_BASE[i]; i++) all[n++] = KILL_BASE[i];
    if (O.kill_streaming) for (int i = 0; KILL_STREAM[i]; i++) all[n++] = KILL_STREAM[i];
    for (int i = 0; i < O.n_extra && n < 46; i++) all[n++] = O.extra[i];
    all[n] = NULL;
    int k = signal_procs(all, NULL, SIGTERM);
    say("freeing RAM: signalled %d process(es)", k);
    sleep(2);
    signal_procs(all, NULL, SIGKILL);
    sleep(1);
}

/* ------------------------------------------------------- loop-device helpers */

static int attach_loop(const char *img, char *devout, size_t sz, int *loopfd)
{
    int imgfd = open(img, O_RDONLY | O_CLOEXEC);
    if (imgfd < 0) { say("open %s: %s", img, strerror(errno)); return -1; }

    int first = -1;
    int ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
    if (ctl >= 0) { first = ioctl(ctl, LOOP_CTL_GET_FREE); close(ctl); }

    for (int tries = 0; tries < 64; tries++) {
        int idx = (first >= 0 && tries == 0) ? first : (first >= 0 ? first + tries : tries);
        char dev[32];
        snprintf(dev, sizeof dev, "/dev/loop%d", idx);
        if (!exists(dev)) mknod(dev, S_IFBLK | 0600, makedev(7, (unsigned)idx));
        int fd = open(dev, O_RDWR | O_CLOEXEC);
        if (fd < 0) continue;
        if (ioctl(fd, LOOP_SET_FD, imgfd) != 0) { close(fd); continue; }
        struct loop_info64 li;
        memset(&li, 0, sizeof li);
        snprintf((char *)li.lo_file_name, sizeof li.lo_file_name, "%s", img);
        li.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;
        if (ioctl(fd, LOOP_SET_STATUS64, &li) != 0) {
            say("LOOP_SET_STATUS64 on %s: %s", dev, strerror(errno));
            ioctl(fd, LOOP_CLR_FD, 0);
            close(fd);
            continue;
        }
        close(imgfd);
        snprintf(devout, sz, "%s", dev);
        *loopfd = fd;                       /* keep open until squashfs is mounted */
        return 0;
    }
    close(imgfd);
    say("no free loop device");
    return -1;
}

/* ---------------------------------------------------------------- mounts */

static int mount_layout(const char *img)
{
    char loopdev[32];
    int lfd = -1;
    mkdir_p(NR, 0755);
    if (attach_loop(img, loopdev, sizeof loopdev, &lfd) != 0) return -1;
    {
        FILE *f = fopen(W "/loopdev", "w");
        if (f) { fprintf(f, "%s\n", loopdev); fclose(f); }
    }
    say("image %s on %s", img, loopdev);
    int rc = do_mount(loopdev, NR, "squashfs", MS_RDONLY, NULL);
    close(lfd);
    if (rc) return -1;

    if (do_mount("proc", NR "/proc", "proc", 0, NULL)) return -1;
    if (do_mount("/sys", NR "/sys", NULL, MS_BIND | MS_REC, NULL)) return -1;
    if (do_mount("/dev", NR "/dev", NULL, MS_BIND | MS_REC, NULL)) return -1;
    /* keep our device masks from propagating back to Tizen's real /dev */
    if (do_mount(NULL, NR "/dev", NULL, MS_PRIVATE | MS_REC, NULL)) return -1;
    if (mask_devices() != 0) return -1;
    /* --rbind, not --bind: /run/user/5001 is its own tmpfs mount and a plain bind
     * would hide it (and enlightenment's Wayland socket) */
    if (do_mount("/run", NR "/run", NULL, MS_BIND | MS_REC, NULL)) return -1;
    if (do_mount("/", NR "/host", NULL, MS_BIND, NULL)) return -1;
    if (do_mount(NULL, NR "/host", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL)) return -1;
    return 0;
}

static void kill_chroot_procs(int sig)
{
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 1 || pid == getpid()) continue;
        char p[64], tgt[256];
        snprintf(p, sizeof p, "/proc/%d/root", pid);
        ssize_t n = readlink(p, tgt, sizeof tgt - 1);
        if (n <= 0) continue;
        tgt[n] = 0;
        if (!strcmp(tgt, NR)) kill(pid, sig);
    }
    closedir(d);
}

static void kill_pidfile(const char *file, int group)
{
    char b[32];
    if (slurp(file, b, sizeof b) <= 0) return;
    pid_t p = (pid_t)atoi(b);
    if (p > 1) kill(group ? -p : p, SIGTERM);
}

static void teardown(void)
{
    say("teardown: stopping session, agent and chroot processes");
    kill_pidfile(W "/session.pid", 0);
    kill_pidfile(W "/agent.pid", 1);
    kill_chroot_procs(SIGTERM);
    sleep(2);
    kill_chroot_procs(SIGKILL);
    sleep(1);
    static const char *const order[] = {
        NR "/host", NR "/run", NR "/dev", NR "/sys", NR "/proc", NR, NULL
    };
    for (int i = 0; order[i]; i++) {
        if (umount2(order[i], MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT)
            say("umount %s: %s", order[i], strerror(errno));
    }
    char ld[64];
    if (slurp(W "/loopdev", ld, sizeof ld) > 0) {
        trim(ld);
        int fd = open(ld, O_RDWR | O_CLOEXEC);
        if (fd >= 0) { ioctl(fd, LOOP_CLR_FD, 0); close(fd); }
    }
    umount2(USBDIR, MNT_DETACH);
    umount2(NETDIR, MNT_DETACH);
    say("teardown finished");
}

/* ----------------------------------------------------------- host-agent etc */

static int start_agent(const char *script)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        setsid();
        int lf = open(W "/host-agent.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) dup2(dn, 0);
        if (lf >= 0) { dup2(lf, 1); dup2(lf, 2); }
        /* respawn loop, as the spec suggests */
        execl("/bin/sh", "sh", "-c", "while :; do sh \"$1\"; sleep 1; done", "sh", script, (char *)NULL);
        _exit(127);
    }
    FILE *f = fopen(W "/agent.pid", "w");
    if (f) { fprintf(f, "%d\n", p); fclose(f); }
    return 0;
}

static const char *find_agent(char *buf, size_t sz)
{
    if (O.agent) return O.agent;
    static const char *const cands[] = {
        USBDIR "/host-agent.sh", USBDIR "/host/host-agent.sh",
        NR "/usr/lib/unshackle/host/host-agent.sh", NR "/usr/lib/unshackle/host-agent.sh",
        NR "/opt/unshackle/host/host-agent.sh", NULL
    };
    for (int i = 0; cands[i]; i++)
        if (exists(cands[i])) { snprintf(buf, sz, "%s", cands[i]); return buf; }
    return NULL;
}

static int conf_wants_fbdev(void)
{
    FILE *f = fopen(RUNDIR "/user.conf", "r");
    if (!f) return 0;
    char l[512];
    int fb = 0;
    while (fgets(l, sizeof l, f)) {
        trim(l);
        if (strncmp(l, "GFX_BACKEND=", 12)) continue;
        char *v = l + 12;
        if (*v == '"' || *v == '\'') v++;
        fb = !strncmp(v, "fbdev", 5);
    }
    fclose(f);
    return fb;
}

static void save_logs(void)
{
    const char *dst = NULL;
    if (g_usb_mounted && usb_make_rw() == 0) dst = USBDIR;
    else if (O.logdir && write_ok(O.logdir)) { mkdir_p(O.logdir, 0755); dst = O.logdir; }
    else if (O.logdir) say("refusing --logdir %s: not tmpfs or the USB stick", O.logdir);
    if (!dst) { say("no writable place for logs (no USB stick); they remain in %s until reboot. "
                       "Plug a stick in to keep them", W); return; }
    static const char *const files[] = {
        W "/switcher.log", W "/session.log", W "/host-agent.log",
        RUNDIR "/gfx-report.txt", RUNDIR "/fiwd.log", RUNDIR "/wl-globals.txt", RUNDIR "/stage", NULL
    };
    for (int i = 0; files[i]; i++) {
        char to[300];
        const char *bn = strrchr(files[i], '/') + 1;
        snprintf(to, sizeof to, "%s/%s", dst, bn);
        copy_file(files[i], to);
    }
    sync();
    say("logs saved to %s", dst);
}

static void fail_and_restore(const char *why)
{
    say("FAILURE: %s", why);
    save_logs();
    if (O.no_reboot) { say("--no-reboot given, leaving system as is"); return; }
    if (isatty(2)) {
        say("rebooting in 20s: read the message above (Ctrl-C to stay and inspect %s)", LOGFILE);
        sleep(20);
    }
    sync_reboot();
}

/* --------------------------------------------------------------- main flow */

static void usage(void)
{
    puts("LinuxSwitch " VERSION " - UnshackleOS root switcher\n\n"
         "  --url URL          fetch the image over http:// instead of the USB stick\n"
         "  --scan             scan the local network for a server answering\n"
         "                     :8000/unshackle.squashfs and pick one (also in --menu)\n"
         "  --sha256 HEX       expected SHA-256 of the image (else <url>.sha256 is tried)\n"
         "  --cache DIR        where to store a downloaded image (default: USB stick, else RAM)\n"
         "  --prefer-net       use unshackle.url from the stick even if a local image exists\n"
         "  --download-only    only download/verify the image, then exit\n"
         "  --menu             interactive source picker (USB or network URL); also shown\n"
         "                     automatically on a terminal when no image source is found\n"
         "  --agent PATH       host-agent.sh location (default: stick, then inside image)\n"
         "  --kill PATTERN     extra process cmdline pattern to kill (repeatable, keep-list safe)\n"
         "  --kill-streaming   also kill background Netflix/Cobalt instances\n"
         "  --min-mem MB       RAM gate (default 450)\n"
         "  --wait SEC         seconds to wait for a USB stick (default 10, 2 with --url)\n"
         "  --timeout SEC      health-check timeout (default 45)\n"
         "  --smack LABEL      write LABEL to /proc/self/attr/current before chroot\n"
         "  --logdir DIR       save failure logs here when there is no writable stick\n"
         "  --no-reboot        never reboot on failure (for debugging)\n"
         "  --unsafe-paths     allow --cache/--logdir outside tmpfs and the USB stick (NOT recommended:\n"
         "                     keeps LinuxSwitch away from eMMC by default)\n"
         "  --teardown         stop the session and unmount everything\n"
         "  --reboot           with --teardown: reboot afterwards");
}

static int http_ok(const char *url)
{
    static resp_t rs;
    int st = http_request(url, "GET", 0, &rs);
    if (st < 0) return 0;
    close(rs.r.fd);
    return st == 200;
}


/* ------------------------------------------------------------ LAN discovery */

#define SCAN_PORT      8000
#define SCAN_MAX       16
#define SCAN_CONN_MS   800     /* time allowed for a whole batch of TCP connects */
#define SCAN_BATCH     128

typedef struct { char url[96]; long long size; } found_t;

/* HEAD /unshackle.squashfs on an already-connected socket.
 * Returns the Content-Length when the server really has the image, else -1. */
static long long probe_image(int fd, const char *ip)
{
    struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);

    char req[256];
    int n = snprintf(req, sizeof req,
                     "HEAD /" IMGNAME " HTTP/1.1\r\nHost: %s:%d\r\n"
                     "User-Agent: LinuxSwitch/" VERSION "\r\nConnection: close\r\n\r\n",
                     ip, SCAN_PORT);
    if (send_all(fd, req, (size_t)n) != 0) return -1;

    char buf[2048];
    size_t len = 0;
    buf[0] = 0;
    while (len < sizeof buf - 1) {
        ssize_t k = recv(fd, buf + len, sizeof buf - 1 - len, 0);
        if (k <= 0) break;
        len += (size_t)k;
        buf[len] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    int st = 0;
    if (sscanf(buf, "HTTP/%*s %d", &st) != 1 || st != 200) return -1;
    const char *p = strcasestr(buf, "\r\nContent-Length:");
    long long clen = p ? atoll(p + 17) : 0;
    return clen >= MB ? clen : -1;        /* a real OS image is not tiny */
}

static long ms_since(const struct timespec *t0)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000L + (t.tv_nsec - t0->tv_nsec) / 1000000L;
}

static void scan_range(uint32_t net, uint32_t bcast, uint32_t self,
                       found_t *out, int *nf, int max)
{
    for (uint32_t base = net + 1; base < bcast && *nf < max; base += SCAN_BATCH) {
        struct pollfd pf[SCAN_BATCH];
        uint32_t addr[SCAN_BATCH];
        char hit[SCAN_BATCH];
        int n = 0;

        /* fire off a batch of non-blocking connects in parallel */
        for (uint32_t a = base; a < base + SCAN_BATCH && a < bcast; a++) {
            if (a == self) continue;
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) continue;
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof sa);
            sa.sin_family = AF_INET;
            sa.sin_port = htons(SCAN_PORT);
            sa.sin_addr.s_addr = htonl(a);
            if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0 && errno != EINPROGRESS) {
                close(fd);
                continue;
            }
            pf[n].fd = fd; pf[n].events = POLLOUT; pf[n].revents = 0;
            addr[n] = a; hit[n] = 0;
            n++;
        }

        /* collect results until everyone answered or the batch deadline hits */
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int pending = n;
        while (pending > 0) {
            long left = SCAN_CONN_MS - ms_since(&t0);
            if (left <= 0) break;
            int pr = poll(pf, (nfds_t)n, (int)left);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) break;
            for (int i = 0; i < n; i++) {
                if (pf[i].fd < 0 || !pf[i].revents) continue;
                int err = 0; socklen_t l = sizeof err;
                getsockopt(pf[i].fd, SOL_SOCKET, SO_ERROR, &err, &l);
                if (!err && (pf[i].revents & POLLOUT) && !(pf[i].revents & (POLLERR | POLLHUP))) {
                    hit[i] = 1;                 /* keep the fd open for probing */
                } else {
                    close(pf[i].fd);
                    pf[i].fd = -1;
                }
                pf[i].events = 0;               /* done with this one */
                pf[i].revents = 0;
                pending--;
            }
        }

        /* probe only the hosts that accepted the TCP connection */
        for (int i = 0; i < n; i++) {
            if (pf[i].fd < 0) continue;
            if (hit[i] && *nf < max) {
                struct in_addr ia;
                ia.s_addr = htonl(addr[i]);
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ia, ip, sizeof ip);
                long long sz = probe_image(pf[i].fd, ip);
                if (sz >= 0) {
                    snprintf(out[*nf].url, sizeof out[*nf].url,
                             "http://%s:%d/" IMGNAME, ip, SCAN_PORT);
                    out[*nf].size = sz;
                    (*nf)++;
                }
            }
            close(pf[i].fd);
        }
    }
}

/* Scan every up, non-loopback IPv4 subnet (capped at /22 around our own address). */
static int scan_net(found_t *out, int max)
{
    struct ifaddrs *ifs, *ia;
    if (getifaddrs(&ifs) != 0) { say("getifaddrs failed: %s", strerror(errno)); return 0; }
    int nf = 0;
    uint32_t seen_net[8];
    int n_seen = 0;

    for (ia = ifs; ia && nf < max; ia = ia->ifa_next) {
        if (!ia->ifa_addr || !ia->ifa_netmask || ia->ifa_addr->sa_family != AF_INET) continue;
        if (!(ia->ifa_flags & IFF_UP) || (ia->ifa_flags & IFF_LOOPBACK)) continue;
        uint32_t ip   = ntohl(((struct sockaddr_in *)ia->ifa_addr)->sin_addr.s_addr);
        uint32_t mask = ntohl(((struct sockaddr_in *)ia->ifa_netmask)->sin_addr.s_addr);
        if (mask >= 0xFFFFFFFEu) continue;                 /* /31, /32: nothing to scan */
        if (mask < 0xFFFFFC00u) mask = 0xFFFFFC00u;        /* never more than 1022 hosts */
        uint32_t net = ip & mask, bcast = net | ~mask;

        int dup = 0;
        for (int i = 0; i < n_seen; i++) if (seen_net[i] == net) dup = 1;
        if (dup) continue;
        if (n_seen < 8) seen_net[n_seen++] = net;

        struct in_addr na; na.s_addr = htonl(ip);
        char s[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &na, s, sizeof s);
        say("scanning %s (%s) for :%d/" IMGNAME, ia->ifa_name, s, SCAN_PORT);
        scan_range(net, bcast, ip, out, &nf, max);
    }
    freeifaddrs(ifs);
    return nf;
}

/* Scan, list, let the person pick. Returns 1 and fills out[] on success. */
static int pick_server(char *out, size_t sz)
{
    int tty = isatty(0);
    for (;;) {
        found_t f[SCAN_MAX];
        printf("Scanning local network for :%d/" IMGNAME " ...\n", SCAN_PORT);
        fflush(stdout);
        int n = scan_net(f, SCAN_MAX);
        if (n == 0) {
            printf("No server on this network answered with %s on port %d.\n"
                   "(Is the server running on the PC, and is the TV on the same network?)\n",
                   IMGNAME, SCAN_PORT);
            if (!tty) return 0;
            printf("[r] rescan  [anything else] cancel > ");
            fflush(stdout);
            char ln[64];
            if (!fgets(ln, sizeof ln, stdin) || (ln[0] != 'r' && ln[0] != 'R')) return 0;
            continue;
        }
        for (int i = 0; i < n; i++)
            printf("  %d) %s  (%lld MB)\n", i + 1, f[i].url, f[i].size / MB);
        int pick = 0;
        if (!tty) pick = 0;                       /* non-interactive: first hit */
        else {
            printf("Choose 1-%d [Enter = 1], r = rescan, 0 = cancel > ", n);
            fflush(stdout);
            char ln[64];
            if (!fgets(ln, sizeof ln, stdin)) return 0;
            trim(ln);
            if (ln[0] == 'r' || ln[0] == 'R') continue;
            if (ln[0] == 0) pick = 0;
            else {
                int v = atoi(ln);
                if (v == 0) return 0;
                if (v < 1 || v > n) { printf("Not a valid choice.\n"); continue; }
                pick = v - 1;
            }
        }
        snprintf(out, sz, "%s", f[pick].url);
        return 1;
    }
}

/* Make typed input forgiving:
 *   192.168.1.10                 -> http://192.168.1.10:8000/unshackle.squashfs
 *   192.168.1.10:8000            -> http://192.168.1.10:8000/unshackle.squashfs
 *   http://host:8000/            -> http://host:8000/unshackle.squashfs
 *   http://host:8000/dir/        -> http://host:8000/dir/unshackle.squashfs
 * A full URL with a file name is left alone. */
static void normalize_url(char *dst, size_t sz, const char *in)
{
    char t[2048];
    snprintf(t, sizeof t, "%s", in);
    trim(t);
    if (!strstr(t, "://")) {
        char u[2048];
        snprintf(u, sizeof u, "http://%s", t);
        snprintf(t, sizeof t, "%s", u);
    }
    const char *auth = strstr(t, "://") + 3;
    const char *slash = strchr(auth, '/');
    int has_port = 0;
    {
        size_t alen = slash ? (size_t)(slash - auth) : strlen(auth);
        for (size_t i = 0; i < alen; i++) if (auth[i] == ':') has_port = 1;
    }
    char out[2200];
    if (!slash) {
        snprintf(out, sizeof out, "%s%s/" IMGNAME, t, has_port ? "" : ":" "8000");
    } else if (slash[strlen(slash) - 1] == '/') {
        snprintf(out, sizeof out, "%s" IMGNAME, t);
    } else {
        snprintf(out, sizeof out, "%s", t);
    }
    snprintf(dst, sz, "%s", out);
}

/* Is there really a file behind this URL? (HEAD, falling back to GET.)
 * Checked BEFORE Tizen's UI is stopped, so a typo can never take the TV down. */
static int url_has_image(const char *url)
{
    static resp_t rs;
    int st = http_request(url, "HEAD", 0, &rs);
    if (st >= 0) close(rs.r.fd);
    if (st == 405 || st == 501) {
        st = http_request(url, "GET", 0, &rs);
        if (st >= 0) close(rs.r.fd);
    }
    return st == 200;
}

/* Content-Length of the image, or -1 if the server does not say. */
static long long url_size(const char *url)
{
    static resp_t rs;
    int st = http_request(url, "HEAD", 0, &rs);
    if (st < 0) return -1;
    long long n = (st == 200) ? rs.clen : -1;
    close(rs.r.fd);
    return n;
}

static int run(void)
{
    char image[700] = "";
    char sha_text[512] = "";
    int use_net = 0, ram = 0;
    char url[2048] = "";

    mkdir_p(RUNDIR, 0755);
    mkdir_p(USBDIR, 0755);

    /* 1. locate stick */
    int wait = O.wait_sec >= 0 ? O.wait_sec : (O.url ? 2 : 10);
    g_usb_mounted = find_usb(wait);
    if (g_usb_mounted) say("stick %s mounted at " USBDIR, g_usb_dev);
    else say("no stick found");

    int local = g_usb_mounted && exists(USBDIR "/" IMGNAME);
    int has_urlfile = 0;
    if (O.url) snprintf(url, sizeof url, "%s", O.url);
    else if (g_usb_mounted && slurp(USBDIR "/unshackle.url", url, sizeof url) > 0) {
        char *nl = strchr(url, '\n'); if (nl) *nl = 0;
        trim(url);
        has_urlfile = url[0] != 0;
    }

    /* interactive picker: forced by --menu, or when nothing was found on a terminal */
    static char menu_url[2048];
    if (O.scan && !O.url) {
        if (pick_server(menu_url, sizeof menu_url)) {
            O.url = menu_url;
            snprintf(url, sizeof url, "%s", menu_url);
        } else {
            say("no server picked: leaving Tizen untouched");
            if (g_usb_mounted) umount(USBDIR);
            return 1;
        }
    }
    if (!O.url && isatty(0) && (O.menu || (!local && !has_urlfile))) {
        for (;;) {
            char ln[2300];
            printf("\n== LinuxSwitch ==\n  1) USB stick%s\n  2) Network: auto-scan for a server\n"
                   "  3) Network: type an address / URL\n  4) Quit\n> ",
                   local ? " (image found)" : "");
            fflush(stdout);
            if (!fgets(ln, sizeof ln, stdin)) { if (g_usb_mounted) umount(USBDIR); return 0; }
            trim(ln);
            if (ln[0] == '1') {
                if (!g_usb_mounted) g_usb_mounted = find_usb(wait > 3 ? wait : 3);
                local = g_usb_mounted && exists(USBDIR "/" IMGNAME);
                has_urlfile = 0;
                if (g_usb_mounted && !local && slurp(USBDIR "/unshackle.url", url, sizeof url) > 0) {
                    char *nl = strchr(url, '\n'); if (nl) *nl = 0;
                    trim(url);
                    has_urlfile = url[0] != 0;
                }
                if (local || has_urlfile) break;
                printf("No unshackle.squashfs / unshackle.url on a stick. Insert one and retry.\n");
            } else if (ln[0] == '2') {
                if (!pick_server(menu_url, sizeof menu_url)) continue;
                O.url = menu_url;
                snprintf(url, sizeof url, "%s", menu_url);
                break;
            } else if (ln[0] == '3') {
                printf("Address or URL (e.g. 192.168.1.10 or http://192.168.1.10:8000/unshackle.squashfs): ");
                fflush(stdout);
                char typed[2048];
                if (!fgets(typed, sizeof typed, stdin)) continue;
                trim(typed);
                if (!typed[0]) continue;
                if (!strncasecmp(typed, "https://", 8)) { printf("https:// is not supported (no TLS in this build). Use http://\n"); continue; }
                normalize_url(menu_url, sizeof menu_url, typed);
                printf("Checking %s ...\n", menu_url);
                if (!url_has_image(menu_url)) {
                    printf("Nothing to download there (wrong port or path, or server not running). Try again.\n");
                    continue;
                }
                O.url = menu_url;
                snprintf(url, sizeof url, "%s", menu_url);
                break;
            } else if (ln[0] == '4' || ln[0] == 'q' || ln[0] == 'Q') {
                if (g_usb_mounted) umount(USBDIR);
                return 0;
            }
        }
    }

    if (O.url) use_net = 1;
    else if (local && !(O.prefer_net && has_urlfile)) use_net = 0;
    else if (has_urlfile) use_net = 1;
    else {
        say("no image (no %s on stick, no --url, no unshackle.url): leaving Tizen untouched", IMGNAME);
        if (g_usb_mounted) umount(USBDIR);
        return 0;
    }

    /* 2. optional overrides */
    if (g_usb_mounted && exists(USBDIR "/unshackle.conf")) {
        copy_file(USBDIR "/unshackle.conf", RUNDIR "/user.conf");
        say("copied unshackle.conf from stick");
    } else if (use_net) {
        char base[2048], cu[2100], conf[8192];
        snprintf(base, sizeof base, "%s", url);
        char *q = strrchr(base, '/');
        if (q && q > strstr(base, "//") + 1) { q[1] = 0;
            snprintf(cu, sizeof cu, "%sunshackle.conf", base);
            int n = fetch_small(cu, conf, sizeof conf);
            if (n > 0) {
                FILE *f = fopen(RUNDIR "/user.conf", "w");
                if (f) { fwrite(conf, 1, (size_t)n, f); fclose(f); }
                say("fetched unshackle.conf from %s", cu);
            }
        }
    }

    /* 3. acquire image */
    int killed = 0;
    if (!use_net) {
        snprintf(image, sizeof image, "%s", USBDIR "/" IMGNAME);
        if (slurp(USBDIR "/" IMGNAME ".sha256", sha_text, sizeof sha_text) > 0 &&
            sha_verify(image, sha_text) != 0) {
            say("local image failed verification: leaving Tizen untouched");
            umount(USBDIR);
            return 1;
        }
    } else {
        const char *dir;
        if (O.cache) dir = O.cache;
        else if (g_usb_mounted && usb_make_rw() == 0) dir = USBDIR;
        else { dir = NETDIR; ram = 1; }
        if (!write_ok(dir)) {
            say("refusing to write to %s: not tmpfs or the USB stick (eMMC protection). "
                "Use a USB stick, or --unsafe-paths if you really mean it.", dir);
            if (g_usb_mounted) umount(USBDIR);
            return 1;
        }
        say("network image: %s (cache: %s%s)", url, dir, ram ? ", RAM" : "");

        /* preflight: make sure the file exists BEFORE Tizen's UI gets stopped */
        if (!url_has_image(url)) {
            say("%s is not reachable / has no image (wrong port or path?): leaving Tizen untouched", url);
            if (g_usb_mounted) umount(USBDIR);
            return 1;
        }

        /* RAM cache: prove it can work BEFORE any Tizen process is stopped. A failure
         * after free_ram() means a reboot, so every check that can be done early is. */
        if (ram) {
            long long total = url_size(url);
            if (total <= 0) {
                say("server did not report a size; a RAM download needs one. Use a USB stick: leaving Tizen untouched");
                return 1;
            }
            /* a private tmpfs sized for the image, so /tmp's own size cap cannot bite */
            mkdir_p(NETDIR, 0755);
            char opt[64];
            snprintf(opt, sizeof opt, "size=%lldm", total / MB + 64);
            if (mount("tmpfs", NETDIR, "tmpfs", MS_NOSUID | MS_NODEV, opt) != 0)
                say("could not mount a private tmpfs (%s); using /tmp's tmpfs", strerror(errno));
            struct statvfs sv;
            if (statvfs(NETDIR, &sv) == 0) {
                long long freeb = (long long)sv.f_bavail * (long long)sv.f_frsize;
                if (freeb < total) {
                    say("only %lld MB of tmpfs space for a %lld MB image. Plug in a USB stick "
                        "(it is then used as the cache). Leaving Tizen untouched", freeb / MB, total / MB);
                    umount(NETDIR);
                    return 1;
                }
            }
            say("RAM cache: image %lld MB, MemAvailable now %ld MB (more after Tizen apps stop)",
                total / MB, mem_avail_mb());
        }

        if (O.sha) snprintf(sha_text, sizeof sha_text, "%s", O.sha);
        else {
            char su[2100];
            snprintf(su, sizeof su, "%s.sha256", url);
            int n = fetch_small(su, sha_text, sizeof sha_text);
            if (n <= 0) { sha_text[0] = 0; say("no .sha256 next to the image; skipping hash check"); }
        }

        if (ram && !O.download_only) { free_ram(); killed = 1; }  /* need the RAM first */
        if (fetch_image(url, dir, sha_text[0] ? sha_text : NULL, ram, image, sizeof image) != 0) {
            if (killed) fail_and_restore("network image unavailable");
            else {
                if (ram) umount(NETDIR);
                if (g_usb_mounted) umount(USBDIR);
            }
            return 1;
        }
    }
    if (O.download_only) { say("download-only: done (%s)", image); return 0; }

    /* 4. free RAM + gate */
    if (conf_wants_fbdev()) { say("GFX_BACKEND=fbdev: stopping enlightenment"); }
    if (!killed) free_ram();
    long avail = mem_avail_mb();
    say("MemAvailable: %ld MB (gate %ld MB)", avail, O.min_mem);
    if (avail >= 0 && avail < O.min_mem) {
        fail_and_restore("not enough free RAM");
        return 1;
    }

    /* 5. mounts */
    if (mount_layout(image) != 0) { fail_and_restore("mount layout failed"); return 1; }

    /* 6. host-agent (before session) */
    char abuf[700];
    const char *agent = find_agent(abuf, sizeof abuf);
    if (agent) { say("starting host-agent: %s", agent); start_agent(agent); }
    else say("WARNING: host-agent.sh not found; Tizen tiles/reboot buttons won't work");

    /* fbdev needs the framebuffer free */
    if (conf_wants_fbdev()) { signal_procs(NULL, "enlightenment", SIGTERM); sleep(2); }

    /* 7. enter */
    mkdir_p(W, 0755);
    pid_t sp = fork();
    if (sp < 0) { fail_and_restore("fork failed"); return 1; }
    if (sp == 0) {
        setsid();
        int lf = open(W "/session.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) dup2(dn, 0);
        if (lf >= 0) { dup2(lf, 1); dup2(lf, 2); }
        if (O.smack) {
            int fd = open("/proc/self/attr/current", O_WRONLY);
            if (fd >= 0) { if (write(fd, O.smack, strlen(O.smack)) < 0) perror("smack"); close(fd); }
        }
        if (chroot(NR) != 0 || chdir("/") != 0) { perror("chroot"); _exit(126); }
        char *envp[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root", "TERM=linux", NULL
        };
        char *argv[] = { "session", NULL };
        execve("/usr/lib/unshackle/session", argv, envp);
        perror("execve session");
        _exit(127);
    }
    {
        FILE *f = fopen(W "/session.pid", "w");
        if (f) { fprintf(f, "%d\n", sp); fclose(f); }
    }
    say("session started, pid %d", sp);

    /* 8. health gate */
    for (int i = 0; i < O.timeout; i++) {
        int status;
        if (waitpid(sp, &status, WNOHANG) == sp) { fail_and_restore("session exited early"); return 1; }
        if (http_ok(API_URL)) {
            char stage[64] = "?";
            slurp(RUNDIR "/stage", stage, sizeof stage);
            trim(stage);
            say("fiwd API is up after %ds (stage: %s) - UnshackleOS running", i, stage);
            return 0;
        }
        sleep(1);
    }
    fail_and_restore("health check timed out");
    return 1;
}

int main(int argc, char **argv)
{
    static const struct option lo[] = {
        {"url", 1, 0, 'u'}, {"sha256", 1, 0, 's'}, {"cache", 1, 0, 'c'}, {"agent", 1, 0, 'a'},
        {"smack", 1, 0, 'S'}, {"logdir", 1, 0, 'l'}, {"kill", 1, 0, 'k'}, {"min-mem", 1, 0, 'm'},
        {"wait", 1, 0, 'w'}, {"timeout", 1, 0, 't'}, {"prefer-net", 0, 0, 'p'},
        {"kill-streaming", 0, 0, 'K'}, {"no-reboot", 0, 0, 'n'}, {"download-only", 0, 0, 'd'},
        {"menu", 0, 0, 'M'}, {"scan", 0, 0, 'N'}, {"unsafe-paths", 0, 0, 'U'}, {"teardown", 0, 0, 'T'}, {"reboot", 0, 0, 'R'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
        switch (c) {
        case 'u': O.url = optarg; break;
        case 's': O.sha = optarg; break;
        case 'c': O.cache = optarg; break;
        case 'a': O.agent = optarg; break;
        case 'S': O.smack = optarg; break;
        case 'l': O.logdir = optarg; break;
        case 'k': if (O.n_extra < 16) O.extra[O.n_extra++] = optarg; break;
        case 'm': O.min_mem = atol(optarg); break;
        case 'w': O.wait_sec = atoi(optarg); break;
        case 't': O.timeout = atoi(optarg); break;
        case 'p': O.prefer_net = 1; break;
        case 'K': O.kill_streaming = 1; break;
        case 'n': O.no_reboot = 1; break;
        case 'd': O.download_only = 1; break;
        case 'M': O.menu = 1; break;
        case 'N': O.scan = 1; break;
        case 'U': O.unsafe_paths = 1; break;
        case 'T': O.teardown = 1; break;
        case 'R': O.reboot_after = 1; break;
        default: usage(); return c == 'h' ? 0 : 2;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    if (!write_ok(W) || !write_ok(RUNDIR)) {
        fprintf(stderr, "[LinuxSwitch] refusing to start: %s or %s is not on tmpfs, so "
                "working there could touch eMMC. (--unsafe-paths overrides.)\n", W, RUNDIR);
        return 1;
    }
    mkdir_p(W, 0755);
    g_log = fopen(LOGFILE, "a");
    say("LinuxSwitch " VERSION " starting");

    if (geteuid() != 0) say("WARNING: not running as root; mounts and chroot will fail");

    if (O.teardown) {
        teardown();
        if (O.reboot_after) sync_reboot();
        return 0;
    }
    return run();
}
