/*
 * DIRTYFAIL — copyfail.h
 *
 * Public surface for the Copy Fail (CVE-2026-31431) module.
 */

#ifndef DIRTYFAIL_COPYFAIL_H
#define DIRTYFAIL_COPYFAIL_H

#include "common.h"

/* Run all preflight checks and the sentinel-file primitive probe.
 * Never modifies system files. */
df_result_t copyfail_detect(void);

/* Real PoC: flip the running user's 4-digit UID in /etc/passwd page
 * cache to "0000" and (optionally) execve `su <user>` to drop a root
 * shell. `do_shell` controls whether to invoke su; if false, the patch
 * is reverted via POSIX_FADV_DONTNEED before returning so the system
 * does not stay in a broken state. */
df_result_t copyfail_exploit(bool do_shell);

#endif
