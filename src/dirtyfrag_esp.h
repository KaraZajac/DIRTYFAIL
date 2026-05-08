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

/* OUTER (init namespace): user prompts → resolve target → fork →
 * wait for child to do the kernel work → read global page cache to
 * verify → if do_shell, execlp("su", user) in init ns for REAL
 * init-ns root via PAM. */
df_result_t dirtyfrag_esp_exploit(bool do_shell);

/* INNER (bypass userns): runs after AA bypass stage 2. Reads
 * DIRTYFAIL_TARGET_USER from env, registers XFRM SA with seq_hi
 * "0000", fires the splice trigger. No prompts, no su, no verify —
 * the parent owns those. Exits with df_result_t cast to int. */
df_result_t dirtyfrag_esp_exploit_inner(void);

#endif
