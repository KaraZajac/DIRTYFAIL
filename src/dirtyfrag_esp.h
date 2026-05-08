/*
 * DIRTYFAIL — dirtyfrag_esp.h
 *
 * Public surface for the Dirty Frag xfrm-ESP variant (CVE-2026-43284).
 */

#ifndef DIRTYFAIL_DIRTYFRAG_ESP_H
#define DIRTYFAIL_DIRTYFRAG_ESP_H

#include "common.h"

/* Run all preconditions for the xfrm-ESP primitive. Detection here is
 * precondition-only: we do not register an SA in detect mode because
 * doing so requires a fresh user namespace and side-effects loopback
 * routing inside that namespace. Returns DF_VULNERABLE if all
 * prerequisites are satisfied. */
df_result_t dirtyfrag_esp_detect(void);

/* Real PoC: chain unshare(USER|NET) → register an XFRM SA carrying our
 * marker bytes in seq_hi → trigger esp_input via UDP-encap+splice on
 * the /etc/passwd page cache, flipping the calling user's 4-digit UID
 * to "0000". Identical end-state to copyfail_exploit() but reaches it
 * via the xfrm path, so it works on systems that have the algif_aead
 * Copy Fail mitigation in place. */
df_result_t dirtyfrag_esp_exploit(bool do_shell);

#endif
