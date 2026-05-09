# DIRTYFAIL — research notes

This document captures kernel-source audits and analysis adjacent to
the published CVEs (CVE-2026-31431 / CVE-2026-43284 / CVE-2026-43500).
It's a living research log, not a vendor advisory: findings here are
based on reading mainline kernel source and the disclosed write-ups,
and may need re-verification as the kernel evolves.

---

## §1. Adjacent kernel paths — audit for the same skb_cow_data() bypass pattern

### TL;DR

Five kernel paths beyond the published CVEs were audited for the same
in-place-AEAD-over-splice-pinned-pages bug class. **All five are
structurally immune.** Two additional candidates (WireGuard and
algif_skcipher) are flagged as open follow-up — see §1.5.

### The vulnerable pattern

The CVE-2026-43284-class bug requires all four of:

1. **In-place AEAD** — `aead_request_set_crypt(req, src, dst, ...)`
   where `src == dst` or the scatterlists alias the same memory.
2. **Conditional skip-COW** — input handler has a branch that bypasses
   `skb_cow_data()` on certain skb shapes (typically: non-linear with
   no frag_list).
3. **`skb_to_sgvec` over skb frags** — the scatterlist passed to the
   AEAD is built directly from the skb's frags, so splice-pinned page
   references end up in it.
4. **Userspace path to the skb's frags** — `splice(2)`, `sendfile(2)`,
   or `sendmsg(MSG_SPLICE_PAGES)` can deliver attacker-controlled
   page-cache pages into those frags.

Removing any one of the four breaks the chain. The published CVEs are
the three sinks where all four conditions align (esp_input, esp6_input,
rxkad_verify_packet_1) plus the algif_aead authencesn / rfc4106-gcm
primitives that share the in-place destination scatterlist pattern.

### §1.1 Path-by-path verdict

| Path | In-place crypto? | skb_cow_data | Splice-reachable? | Verdict |
|---|---|---|---|---|
| esp_input (esp4) | ✅ | conditional skip | yes | **CVE-2026-43284** (patched) |
| esp6_input | ✅ | conditional skip | yes | **CVE-2026-43284 v6** (patched) |
| algif_aead authencesn | ✅ | n/a (different path) | yes via splice→AF_ALG | **CVE-2026-31431** (patched) |
| algif_aead rfc4106-gcm | ✅ | n/a | yes | **Copy Fail GCM variant** (patched as side-effect of CF revert) |
| rxkad_verify_packet_1 | ✅ | conditional skip | yes via RxRPC handshake | **CVE-2026-43500** (NOT patched as of 2026-05-09) |
| **ah_input (ah4 + ah6)** | ✅ (HMAC, not decrypt) | **UNCONDITIONAL** | n/a | NOT vulnerable — structurally immune |
| **ipcomp_input** | ❌ (decompress, separate output pages) | conditional skip | n/a (output is fresh page) | NOT vulnerable — separate dst |
| **macsec_decrypt** | ✅ | **UNCONDITIONAL** | no — rx skbs come from netdev | NOT vulnerable — structurally immune |
| **tls_sw recv decrypt** | ✅ | unconditional, also rx-only | no — rx skbs come from TCP rx ring | NOT vulnerable |
| **tls_sw send encrypt + MSG_SPLICE_PAGES** | YES (read-only on user pages) | n/a (msg_en allocated separately) | yes (msg_pl) but only as src | NOT vulnerable — separate src/dst |

### §1.2 Eliminated paths — why each is immune

**`ah_input` (net/ipv4/ah4.c, net/ipv6/ah6.c)** — IPsec Authentication
Header. Calls `skb_cow_data(skb, 0, &trailer)` UNCONDITIONALLY before
`skb_to_sgvec_nomark` builds the HMAC scatterlist. No skip-cow branch.
Splice-pinned pages would always be copied into a private buffer
before HMAC verification.

**`xfrm_ipcomp.c`** — IPCOMP decompression has a conditional skip-cow
branch, but the output is allocated as a fresh kernel page
(`alloc_page(GFP_ATOMIC)`) and the destination scatterlist `dsg` is
built separately from the input scatterlist `sg`. Even with
splice-pinned input pages, decompression output goes to fresh pages.
Not in-place over input.

**`macsec_decrypt` (drivers/net/macsec.c)** — MACsec receive AEAD.
Calls `skb_cow_data(skb, 0, &trailer)` unconditionally before
`skb_to_sgvec` and the in-place decrypt. Additionally: macsec rx
skbs come from netdev rx, not from userspace splice — the attacker
has no path to plant a page-cache page reference.

**`tls_sw_recvmsg` (net/tls/tls_sw.c)** — kTLS receive AEAD.
kernel.org docs: "To decrypt 'in place' kTLS calls skb_cow_data()."
COW is unconditional on the rx path. Additionally: TLS rx skbs come
from the TCP rx queue, not from splice — the only way a user can put
a page-cache page reference into a TCP rx skb is via rare
`SO_PEEK_OFF` / `MSG_PEEK` paths or kernel-side socket forwarding,
neither of which gives the attacker control.

### §1.3 kTLS send via MSG_SPLICE_PAGES — closest near-miss

The kTLS *send* path was modified in 2023 ("splice, net: Handle
MSG_SPLICE_PAGES in AF_TLS", LWN 933386) to support
`MSG_SPLICE_PAGES`, which is the same primitive Dirty Frag and Copy
Fail abuse. This was the most plausible adjacent candidate.

**Resolved: not vulnerable.** Direct reading of `net/tls/tls_sw.c`:

- `tls_sw_sendmsg_splice()` adds the user's spliced pages to `msg_pl`
  (the plaintext sk_msg buffer) via `sk_msg_page_add()`.
- `tls_alloc_encrypted_msg()` calls
  `sk_msg_alloc(sk, msg_en, len, 0)` — **fresh kernel pages** for the
  encrypted buffer.
- `tls_push_record()` chains the scatterlists:
  ```c
  sg_chain(rec->sg_aead_out, 2, &msg_en->sg.data[i]);
  ```
- `tls_do_encryption()`:
  ```c
  aead_request_set_crypt(aead_req, rec->sg_aead_in,
                         rec->sg_aead_out, data_len, rec->iv_data);
  ```
- `sg_aead_in` (chained from msg_pl, contains user's spliced page)
  ≠ `sg_aead_out` (chained from msg_en, kernel-allocated pages).

The encrypt READS the user's spliced /etc/passwd page but WRITES
ciphertext to `msg_en`'s kernel-allocated pages. The user's
page-cache page is never modified. This is exactly the defense the
algif_aead patch (a664bf3d603d) implemented when it reverted to
out-of-place AEAD; kTLS has had it from inception.

Compare to the vulnerable `esp_input` pattern:

```c
/* vulnerable: src == dst */
skb_to_sgvec(skb, sg, ...);
aead_request_set_crypt(req, sg, sg, ...);
```

```c
/* safe: src ≠ dst */
sg_chain(sg_aead_in,  ..., msg_pl);   /* user spliced pages    */
sg_chain(sg_aead_out, ..., msg_en);   /* kernel private pages  */
aead_request_set_crypt(req, sg_aead_in, sg_aead_out, ...);
```

### §1.4 The protective patterns that distinguish safe from vulnerable

Every safe path on the list achieves immunity through one of three
mechanisms, each of which removes one of the four required conditions:

1. **Unconditional `skb_cow_data()`** before any in-place crypto —
   AH, MACsec, kTLS rx. (Removes condition 2.)
2. **Separate destination scatterlist** allocated from kernel-private
   pages — kTLS tx, IPCOMP, post-patch algif_aead.
   (Removes condition 1.)
3. **The in-place crypto target is fundamentally not a splice-able
   skb** — kTLS rx skbs come from TCP rx, not user splice.
   (Removes condition 4.)

### §1.5 Open candidates not yet audited

These are kernel paths that *might* match the bug class but haven't
been fully read yet. Listed in priority order.

**HIGH — WireGuard (`drivers/net/wireguard/receive.c`)**
ChaCha20Poly1305 in-place AEAD on incoming UDP skbs. WireGuard is
widespread (kernel-resident since 5.6) and processes skbs that may
carry frags from various sources. The question: does
`wg_packet_decrypt_worker()` (or its scatterlist-building helper)
call `skb_cow_data()` unconditionally before the AEAD, or does it
have a skip-cow branch like esp_input? **Best single candidate**;
structurally most similar to ESP among unaudited paths.

**HIGH — `algif_skcipher` (`crypto/algif_skcipher.c`)**
Same author and patchset era as the algif_aead in-place
optimization that introduced Copy Fail (2017, commit 72548b093ee3).
The Copy Fail upstream fix only reverted `algif_aead`; if
`algif_skcipher` shares the splice-into-dst-SGL pattern,
there's potentially an undisclosed CVE in the same module family.
Worth a careful read of `_skcipher_recvmsg()` and the AF_ALG
operation socket setup.

**MEDIUM — `espintcp` (`net/xfrm/espintcp.c`)**
IPsec ESP carried over TCP rather than UDP. Different transport,
different `skb` shape. The mainline patch (f4c50a4034e6) probably
covers this if it shared `esp_input` callsites, but worth confirming
the SHARED_FRAG flag check propagated.

**MEDIUM — OpenVPN kernel offload (`drivers/net/ovpn/`)**
New module in 6.16+. ChaCha20Poly1305 / AES-GCM in-place. Less
mature, less audited.

**MEDIUM — SCTP-AUTH (`net/sctp/auth.c`)**
HMAC validation on incoming chunks. Almost certainly uses
`skb_cow_data` unconditionally (like AH), but worth a 30-minute
trace to confirm. SCTP is default-enabled on RHEL/CentOS, narrower
reach.

**LOW**

- AF_SMC encryption — uses kTLS/ULP underneath, probably already
  covered by the kTLS audit.
- io_uring crypto extensions — if any exist, would inherit AF_ALG
  semantics.
- Bluetooth CMTP/HIDP crypto — privileged-only, not LPE-relevant.
- Kernel TLS NIC offload — different threat surface (NIC-side).

### §1.6 Methodology

For each candidate path, read the input handler and ask:

1. Does it call `skb_cow_data()` BEFORE building the AEAD
   scatterlist?
2. Is there a conditional branch (typically based on `skb_cloned`,
   `skb_has_frag_list`, `skb_is_nonlinear`) that bypasses (1)?
3. Is the resulting scatterlist used as BOTH src AND dst of
   `aead_request_set_crypt()` / equivalent?
4. Can a userspace primitive (`splice(2)`, `sendfile(2)`,
   `sendmsg(MSG_SPLICE_PAGES)`, AF_ALG send) deliver
   attacker-controlled pages into the input skb's frags?

All four must be true for the bug class to apply. A single "no" is
sufficient for "not vulnerable."

---

## §2. References

- V4bel/dirtyfrag write-up — [github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md](https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md)
- Theori/Xint Copy Fail disclosure — [xint.io/blog/copy-fail-linux-distributions](https://xint.io/blog/copy-fail-linux-distributions)
- LWN — Replace sendpage with sendmsg(MSG_SPLICE_PAGES) — [lwn.net/Articles/928487](https://lwn.net/Articles/928487/)
- LWN — Handle MSG_SPLICE_PAGES in AF_TLS — [lwn.net/Articles/933386](https://lwn.net/Articles/933386/)
- TLS 1.3 Rx improvements (Kicinski) — [people.kernel.org/kuba/tls-1-3-rx-improvements-in-linux-5-20](https://people.kernel.org/kuba/tls-1-3-rx-improvements-in-linux-5-20)
- 0xdeadbeefnetwork Copy_Fail2 (GCM variant) — [github.com/0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo](https://github.com/0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo)
- Linux source (torvalds/master) — `net/ipv4/ah4.c`, `net/ipv6/ah6.c`, `net/xfrm/xfrm_ipcomp.c`, `drivers/net/macsec.c`, `net/tls/tls_sw.c`
