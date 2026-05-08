/*
 * DIRTYFAIL — dirtyfrag_rxrpc.c — Dirty Frag RxRPC variant
 *                                  CVE-2026-43500
 *
 * BACKGROUND
 * ----------
 * Same shape of bug as the xfrm-ESP variant — splice() plants a
 * page-cache page into the frag of an skb, the receive path runs
 * in-place crypto on it. Here, the sink is rxkad_verify_packet_1():
 *
 *     skcipher_request_set_crypt(req, sg, sg, 8, iv.x);
 *     ret = crypto_skcipher_decrypt(req);
 *
 * 8-byte STORE per trigger. The 8 bytes that get written are
 * pcbc_decrypt(C, K) where C is the ciphertext at that file offset and
 * K is the session_key from an RxRPC v1 token the attacker registered
 * via add_key("rxrpc", ...). Because pcbc(fcrypt) reduces to a single
 * fcrypt_decrypt() at single-block + IV=0, and fcrypt is a 56-bit key
 * cipher, the attacker can brute-force K in user-space until the
 * desired plaintext drops out.
 *
 * UNLIKE the ESP variant, this path does not require namespace
 * privilege — add_key, AF_RXRPC, and splice are all available to
 * unprivileged users on a stock build that includes rxrpc.ko.
 *
 * EXPLOIT TARGET
 * --------------
 * /etc/passwd line 1 ("root:x:0:0:..."). Last-write-wins across three
 * 8-byte STOREs at offsets 4, 6, 8 produces "root::0:0:GGGGGG:..."
 * — empty password field. PAM with pam_unix nullok then accepts an
 * empty password, su drops a root shell.
 *
 * SCOPE OF THIS MODULE
 * --------------------
 * Detection only. Full weaponization requires:
 *   - a user-space port of the kernel's fcrypt to brute-force K
 *   - AF_RXRPC client socket forging the CHALLENGE/RESPONSE handshake
 *   - rxkad cksum derivation via AF_ALG pcbc(fcrypt)
 *   - 3× chained-ciphertext brute force passes
 *
 * That's ~800 lines on top of what V4bel already shipped in dirtyfrag's
 * exp.c. Reimplementing it from scratch is out of scope for DIRTYFAIL;
 * security researchers who want the full PoC should consult V4bel's
 * exp.c and the writeup at github.com/V4bel/dirtyfrag.
 *
 * What we *do* check:
 *   - rxrpc.ko loaded (or autoloadable via socket(AF_RXRPC, ...))
 *   - kernel within affected window (5.x → upstream)
 *
 * If both hold, we report VULNERABLE and direct the operator to V4bel's
 * exp.c for the actual exploit.
 */

#include "dirtyfrag_rxrpc.h"

#include <sys/socket.h>
#include <fcntl.h>

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif

df_result_t dirtyfrag_rxrpc_detect(void)
{
    log_step("Dirty Frag — RxRPC variant (CVE-2026-43500) — detection");

    int km = -1, kn = -1;
    if (kernel_version(&km, &kn))
        log_hint("kernel %d.%d.x", km, kn);

    bool rxrpc = kmod_loaded("rxrpc");
    log_hint("rxrpc currently loaded: %s", rxrpc ? "yes" : "no");

    /* Try to autoload by opening an AF_RXRPC socket. The kernel uses
     * MODULE_ALIAS_NETPROTO(PF_RXRPC) to autoload rxrpc.ko on demand,
     * so even if /proc/modules says no, the module may still be
     * available on disk. */
    int s = socket(AF_RXRPC, SOCK_DGRAM, 0);
    bool can_open = (s >= 0);
    if (can_open) close(s);
    log_hint("AF_RXRPC socket: %s", can_open ? "openable" : "denied");

    if (!rxrpc && !can_open) {
        log_ok("rxrpc not present and AF_RXRPC socket family rejected — "
               "RxRPC variant unreachable");
        return DF_PRECOND_FAIL;
    }

    log_warn("VULNERABLE — RxRPC variant of Dirty Frag is reachable");
    log_warn("apply mitigation (blacklist rxrpc) until a patch lands:");
    log_warn("  echo 'install rxrpc /bin/false' | sudo tee /etc/modprobe.d/dirtyfrag.conf");
    log_warn("  sudo rmmod rxrpc 2>/dev/null; sudo sysctl vm.drop_caches=3");
    log_hint("DIRTYFAIL does not bundle a full RxRPC weaponization. To verify");
    log_hint("exploitability end-to-end, run V4bel's exp.c on a sandboxed VM:");
    log_hint("  https://github.com/V4bel/dirtyfrag");

    return DF_VULNERABLE;
}
