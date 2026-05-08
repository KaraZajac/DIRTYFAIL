/*
 * DIRTYFAIL — dirtyfrag_rxrpc.h
 *
 * RxRPC variant of Dirty Frag (CVE-2026-43500). Detection only.
 */

#ifndef DIRTYFAIL_DIRTYFRAG_RXRPC_H
#define DIRTYFAIL_DIRTYFRAG_RXRPC_H

#include "common.h"

df_result_t dirtyfrag_rxrpc_detect(void);

#endif
