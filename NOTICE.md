# NOTICE

## fcrypt S-box constants and key schedule

`src/fcrypt.c` contains the four 256-byte S-box tables `SBOX0_RAW`,
`SBOX1_RAW`, `SBOX2_RAW`, and `SBOX3_RAW`, along with the 56-bit key
packing and 11-bit-rotation key schedule for the rxkad fcrypt cipher.

These tables and the key schedule are **protocol constants** of the
Andrew File System (AFS) rxkad authentication scheme. They appear
verbatim in:

- The Linux kernel's `crypto/fcrypt.c` (GPL-2.0,
  Copyright © David Howells / KTH)
- IBM's open-source AFS distribution
- OpenAFS upstream
- Heimdal Kerberos (rxkad implementation)

Cryptographic constants required by a wire protocol are facts about
the protocol, not creative expression — using them is what makes
interoperability with the Linux kernel possible. We list this here for
transparency: while the S-box bytes are identical to the kernel's
table, the rest of `src/fcrypt.c` (table preprocessing, brute-force
harness, predicates, splitmix64 search) is independently written
DIRTYFAIL code under the project's MIT license.

If you intend to redistribute DIRTYFAIL in a context where strict
license compatibility matters, treat `src/fcrypt.c` as carrying the
same license obligations as the kernel `crypto/fcrypt.c` source for
the S-box constants alone.

## Reference exploits

The detection and exploit techniques in DIRTYFAIL were studied from:

- [Smarttfoxx/copyfail](https://github.com/Smarttfoxx/copyfail) — Copy
  Fail original C PoC
- [rootsecdev/cve_2026_31431](https://github.com/rootsecdev/cve_2026_31431)
  — Copy Fail Python detector + UID-flip exploit
- [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) — Dirty Frag
  full chain PoC by Hyunwoo Kim ([@v4bel](https://x.com/v4bel))

DIRTYFAIL implementations are independently written in C, organized
around a single binary with detection-first defaults, but the protocol
mechanics (XFRM SA layout, RxRPC handshake forgery, rxkad checksum
formula) are necessarily identical to the upstream PoCs because they
target the same kernel interfaces.

See [README §11 — Credits](README.md#11-credits) for the full list.
