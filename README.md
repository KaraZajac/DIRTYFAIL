# DIRTYFAIL

> A unified detector and PoC harness for the **Copy Fail** and **Dirty Frag**
> Linux page-cache write vulnerability families.

```
 ██████╗ ██╗██████╗ ████████╗██╗   ██╗███████╗ █████╗ ██╗██╗
 ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔════╝██╔══██╗██║██║
 ██║  ██║██║██████╔╝   ██║    ╚████╔╝ █████╗  ███████║██║██║
 ██║  ██║██║██╔══██╗   ██║     ╚██╔╝  ██╔══╝  ██╔══██║██║██║
 ██████╔╝██║██║  ██║   ██║      ██║   ██║     ██║  ██║██║███████╗
 ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝
```

DIRTYFAIL is a small, well-documented C tool for security researchers.
It detects whether a Linux host is vulnerable to the three CVEs in this
family, and — with explicit, typed confirmation — runs a real
proof-of-concept that drops the caller into a root shell on a
vulnerable system.

| CVE | Name | DIRTYFAIL coverage |
|-----|------|--------------------|
| **CVE-2026-31431** | Copy Fail (algif_aead `authencesn` page-cache write) | Detect + full PoC |
| **CVE-2026-43284** | Dirty Frag — xfrm-ESP page-cache write              | Detect + full PoC |
| **CVE-2026-43500** | Dirty Frag — RxRPC page-cache write                 | Detect only       |

> **Authorized testing only.** Use DIRTYFAIL only on systems you own or
> are explicitly engaged to assess. The exploit modes corrupt
> `/etc/passwd` *in the kernel page cache* (the on-disk file is never
> touched). Cleanup is `dirtyfail --cleanup` or
> `echo 3 > /proc/sys/vm/drop_caches`.

---

## Table of contents

1. [The bug class](#1-the-bug-class)
2. [CVE-2026-31431 — Copy Fail](#2-cve-2026-31431--copy-fail)
3. [CVE-2026-43284 — Dirty Frag (xfrm-ESP)](#3-cve-2026-43284--dirty-frag-xfrm-esp)
4. [CVE-2026-43500 — Dirty Frag (RxRPC)](#4-cve-2026-43500--dirty-frag-rxrpc)
5. [Build](#5-build)
6. [Usage](#6-usage)
7. [How DIRTYFAIL detects each CVE](#7-how-dirtyfail-detects-each-cve)
8. [How DIRTYFAIL exploits each CVE](#8-how-dirtyfail-exploits-each-cve)
9. [Mitigations](#9-mitigations)
10. [Ethics & disclosure](#10-ethics--disclosure)
11. [Credits](#11-credits)

---

## 1. The bug class

**Page-cache write** vulnerabilities let an unprivileged user modify
the kernel's in-memory copy of a file they only have read access to.
The on-disk file is never written; the modification persists in RAM
until the page is evicted (`drop_caches`, memory pressure, or reboot).

This class started with **Dirty Pipe** (CVE-2022-0847), which abused
`pipe_buffer` flags. Copy Fail and Dirty Frag are descendants that
target the `frag` member of `struct sk_buff` instead. The mechanism is
always the same:

1. Userspace `splice()`s a page-cache page from a readable file (e.g.
   `/etc/passwd`, `/usr/bin/su`) into the frag of a kernel buffer.
2. A receive path runs **in-place** crypto on that buffer — the same
   pages are both source and destination of the operation.
3. The crypto routine performs a "scratch" STORE outside the data
   region (a sequence-number rearrangement, a single-block decrypt,
   etc.) that lands inside the user-pinned page.
4. The page-cache copy of the file is now permanently modified for
   every reader on the host, until the page is evicted.

Because the bug is a **deterministic logic flaw**, not a race, success
rates are essentially 100% and the kernel does not panic on failure.

---

## 2. CVE-2026-31431 — Copy Fail

* Disclosure: **2026-04-29**
* Site: <https://copy.fail/>
* Original PoC (C):     [Smarttfoxx/copyfail](https://github.com/Smarttfoxx/copyfail)
* Original PoC (Python): [rootsecdev/cve_2026_31431](https://github.com/rootsecdev/cve_2026_31431)
* Introduced by commit:  `72548b093ee3` (2017)
* Fixed by commit:       `a664bf3d` (mainline 6.12 / 6.17 / 6.18 stables)
* Confirmed affected:    Ubuntu 24.04 LTS, Amazon Linux 2023, RHEL 14.3, SUSE 16

### Root cause

The kernel's `algif_aead` module exposes the AEAD crypto API to
userspace via `AF_ALG`. The `authencesn(hmac(sha256), cbc(aes))`
template implements RFC-4303 ESN (Extended Sequence Numbers); part of
its decryption path performs a **4-byte scratch write** to rearrange
the sequence number:

```c
static int crypto_authenc_esn_decrypt(struct aead_request *req)
{
    /* Move high-order bits of sequence number to the end. */
    scatterwalk_map_and_copy(tmp, src, 0, 8, 0);
    if (src == dst) {
        scatterwalk_map_and_copy(tmp,     dst, 4,                  4, 1);
        scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);  // ★
        ...
```

The STORE at ★ is harmless on a normal IPsec packet — it lands inside
the skb's tag area, which is kernel-owned. The crypto template
**assumes** `src` and `dst` point into kernel memory.

`algif_aead` violates that assumption. It accepts `splice()` from
userspace, which plants page-cache pages into the request's
scatterlist. Because the AEAD runs in-place (`req->dst = req->src`),
the page-cache page now sits at the destination scatterlist offset
that the scratch write targets.

The 4 bytes that get written are bytes 4..7 of the AAD that userspace
sent — the "seqno_lo" field of an ESP header, which the attacker fills
with whatever they want.

**Net primitive**: 4-byte arbitrary-offset write into the page cache
of any file the attacker can `open(O_RDONLY)`.

### Exploitation

The simplest weaponization is in `/etc/passwd`. A normal user line
looks like:

```
kara:x:1000:1000:Kara,,,:/home/kara:/bin/bash
```

Flipping `1000` (the UID field, exactly 4 ASCII bytes for any UID
1000–9999) to `0000` makes glibc's `getpwnam()` report uid=0 for
that user. PAM, however, still authenticates against the on-disk
`/etc/shadow` (which is untouched), so `su <user>` prompts for the
real password, validates it, then `setuid(0)` — and lands at root
because the page-cache copy of `/etc/passwd` says we are root.

`/etc/shadow` integrity is preserved. On-disk `/etc/passwd` is
preserved. Only the kernel's RAM copy of `/etc/passwd` is corrupted,
and only until `drop_caches` or reboot.

---

## 3. CVE-2026-43284 — Dirty Frag (xfrm-ESP)

* Disclosure: **2026-04-30 → 2026-05-08**
* Original PoC (C): [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)
* Researcher: Hyunwoo Kim ([@v4bel](https://x.com/v4bel))
* Introduced by commit: `cac2661c53f3` (2017-01-17)
* Fixed by commit:      `f4c50a4034e6` (mainline net.git, merged 2026-05-07)
* Confirmed affected:   Ubuntu 24.04, RHEL 10.1, openSUSE Tumbleweed,
                        CentOS Stream 10, AlmaLinux 10, Fedora 44

### Root cause

`esp_input()` is supposed to call `skb_cow_data()` before in-place AEAD
decryption when an skb is non-linear (i.e. has frags). The code path
has a short-circuit:

```c
if (!skb_cloned(skb)) {
    if (!skb_is_nonlinear(skb)) {
        nfrags = 1;
        goto skip_cow;
    } else if (!skb_has_frag_list(skb)) {        // ★ bug
        nfrags = skb_shinfo(skb)->nr_frags;
        nfrags++;
        goto skip_cow;
    }
}
```

If the skb has frags but no `frag_list`, esp_input bypasses
`skb_cow_data` and hands the user-supplied frag straight to the AEAD
template. The same `authencesn(...)` scratch write that powers Copy
Fail then lands at file offset `(assoclen + cryptlen)` of the spliced
page.

The 4 STOREd bytes are `seq_hi` from the SA's `replay_esn` state —
attacker-controlled at SA registration time via the
`XFRMA_REPLAY_ESN_VAL` netlink attribute.

**Cost**: registering an XFRM SA needs `CAP_NET_ADMIN`, so the
attacker enters a fresh user namespace via `unshare(CLONE_NEWUSER)`
first. This is allowed by default on most distros (Ubuntu's hardened
profile is the notable exception).

**Crucially, this primitive works even when the algif_aead Copy Fail
mitigation is in place** — the xfrm path doesn't go through algif_aead.
A defender who only blacklisted `algif_aead` is still vulnerable to
Dirty Frag.

### Exploitation

V4bel's published PoC writes a 192-byte static "root-shell" ELF over
the first 192 bytes of `/usr/bin/su`'s page cache, using 48 sequential
4-byte STOREs. After modification, `execve("/usr/bin/su")` runs the
new ELF entry point with the setuid-root bit intact, drops PAM
entirely, and `execve("/bin/sh")` from inside the shellcode.

DIRTYFAIL takes the simpler `/etc/passwd` UID-flip approach (one
4-byte STORE — the same target as Copy Fail) for two reasons:

1. It is a single-write primitive demonstration, easier to study.
2. It is fully reversible with `POSIX_FADV_DONTNEED` and does not
   leave `/usr/bin/su` in a corrupt state for other users on the
   system.

---

## 4. CVE-2026-43500 — Dirty Frag (RxRPC)

* Disclosure: **2026-04-29 → 2026-05-08**
* Patch:        not in any tree as of 2026-05-08; researcher's patch
                pending: `lore.kernel.org/all/afKV2zGR6rrelPC7@v4bel/`
* Researcher:   Hyunwoo Kim ([@v4bel](https://x.com/v4bel))
* Introduced by commit: `2dc334f1a63a` (2023-06)

### Root cause

`rxkad_verify_packet_1()` performs an **in-place** `pcbc(fcrypt)`
single-block decryption on the first 8 bytes of an RxRPC data packet:

```c
sg_init_table(sg, ARRAY_SIZE(sg));
ret = skb_to_sgvec(skb, sg, sp->offset, 8);
memset(&iv, 0, sizeof(iv));
skcipher_request_set_crypt(req, sg, sg, 8, iv.x);   // ★ src == dst
ret = crypto_skcipher_decrypt(req);                 // ★ 8-byte STORE
```

If a page-cache page has been spliced into the skb's frag, the 8-byte
decrypt is performed on top of it.

**Difference from xfrm-ESP**: the 8 bytes that get STOREd are
`fcrypt_decrypt(C, K)`, where `C` is the existing ciphertext at that
file offset and `K` is the session key from an RxRPC v1 token the
attacker registered via `add_key("rxrpc", ...)`. The attacker doesn't
control the STORE value directly — they have to brute-force `K` until
`fcrypt_decrypt(C, K)` produces the desired plaintext.

`fcrypt` is an Andrew File System cipher with a **56-bit key** and
8-byte block. It is deterministic; it ports cleanly to user space; and
its key space is small enough that a constrained 8-byte target can be
brute-forced in milliseconds to seconds depending on the constraint
budget.

**Crucially, this path does NOT need namespace privileges** —
`add_key`, `socket(AF_RXRPC)`, `socket(AF_ALG)`, `splice` are all
available to any unprivileged user. RxRPC fills the gap on Ubuntu's
hardened-userns profile (where xfrm-ESP is blocked) because
`rxrpc.ko` ships in the default Ubuntu build.

### Exploitation

The full exploit:

1. Brute-force `K_A`, `K_B`, `K_C` in user-space such that the three
   STOREs at `/etc/passwd` offsets 4, 6, 8 produce
   `"::"`, `"0:"`, `"0:GGGGGG:"` respectively (last-write-wins).
2. For each `K_i`, register an RxRPC v1 token with `add_key`, perform
   a forged AF_RXRPC handshake against a fake UDP server in the same
   process, and trigger `rxkad_verify_packet_1` via splice.
3. The page-cache copy of `/etc/passwd` line 1 is now
   `root::0:0:GGGGGG:/root:/bin/bash` — an empty password field.
4. PAM with `pam_unix.so nullok` accepts the empty password; `su -`
   drops a root shell.

### DIRTYFAIL coverage

DIRTYFAIL **detects** this CVE (kernel version + rxrpc availability +
AF_RXRPC openable) but does **not** ship a full PoC. Reimplementing
the fcrypt brute-force, the AF_RXRPC handshake forgery, and the rxkad
checksum derivation cleanly from scratch is on the order of 800 lines
on top of what is already public.

For end-to-end exploitation testing, run V4bel's `exp.c` on a
sandboxed VM: <https://github.com/V4bel/dirtyfrag>.

---

## 5. Build

### Prerequisites

* **Linux** (this binary is Linux-only at runtime).
* `gcc` or `clang`, `make`.
* Linux UAPI headers — specifically `<linux/xfrm.h>`, `<linux/netlink.h>`,
  `<linux/rtnetlink.h>`, `<linux/if.h>`.

| Distro            | Install                                              |
|-------------------|------------------------------------------------------|
| Debian / Ubuntu   | `sudo apt install build-essential linux-libc-dev`    |
| RHEL / CentOS     | `sudo dnf install gcc make kernel-headers glibc-devel` |
| Fedora            | `sudo dnf install gcc make kernel-headers`           |
| Arch              | `sudo pacman -S base-devel`                          |

### Build commands

```sh
git clone https://github.com/<you>/DIRTYFAIL.git
cd DIRTYFAIL
make                # release build → ./dirtyfail
make debug          # -O0 -g3 for gdb
make static         # static link (musl-gcc recommended)
make clean
```

The default build produces a single ~80 KB binary at `./dirtyfail`.
For a portable build that runs on any kernel-compatible Linux without
glibc dependency drift:

```sh
make static CC=musl-gcc
```

(install `musl-tools` on Debian/Ubuntu, or build musl from source).

---

## 6. Usage

```
$ ./dirtyfail --help
Usage: ./dirtyfail [MODE] [OPTIONS]

Modes (pick one; default is --scan):
  --scan                 detect all three CVEs (no system modification)
  --check-copyfail       Copy Fail (CVE-2026-31431) detection only
  --check-esp            Dirty Frag xfrm-ESP (CVE-2026-43284) detection only
  --check-rxrpc          Dirty Frag RxRPC   (CVE-2026-43500) detection only
  --exploit-copyfail     real PoC: flip /etc/passwd UID via algif_aead
  --exploit-esp          real PoC: flip /etc/passwd UID via xfrm-ESP
  --cleanup              evict /etc/passwd from page cache and drop_caches

Options:
  --no-shell             after a successful exploit, do NOT execve `su`;
                         instead revert the page-cache patch and exit
  --no-color             disable ANSI color in output
```

### Detection (safe; no system modification)

```sh
./dirtyfail --scan
```

Sample output on a vulnerable Ubuntu 24.04:

```
[*] Copy Fail (CVE-2026-31431) — detection
[i] kernel 6.17.x (affected lines: 6.12, 6.17, 6.18)
[+] AF_ALG + authencesn(hmac(sha256),cbc(aes)) loadable
[*] triggering primitive against /tmp/copyfail-sentinel.XXXX with marker 'PWND'
[!] VULNERABLE — marker 'PWND' landed at sentinel offset 24

[*] Dirty Frag — xfrm-ESP variant (CVE-2026-43284) — detection
[i] kernel 6.17.x
[i] esp4 currently loaded: yes
[i] esp6 currently loaded: yes
[i] unprivileged user namespace: allowed
[!] VULNERABLE (preconditions met) — userns + xfrm SA registration available

[*] Dirty Frag — RxRPC variant (CVE-2026-43500) — detection
[i] rxrpc currently loaded: yes
[i] AF_RXRPC socket: openable
[!] VULNERABLE — RxRPC variant of Dirty Frag is reachable
```

### Exploit (requires typed confirmation)

```sh
./dirtyfail --exploit-copyfail
```

You will be prompted to type `DIRTYFAIL` and press enter before any
page-cache modification happens. After a successful flip, DIRTYFAIL
invokes `su <yourname>`; type your **own** password — PAM still
checks against the untouched `/etc/shadow`, then `setuid(0)` lands
at root because the page cache says you are uid 0.

To run the exploit without spawning a shell (useful for CI / repeated
testing):

```sh
./dirtyfail --exploit-copyfail --no-shell
```

This applies the patch, verifies it landed, then evicts
`/etc/passwd` from the page cache via `POSIX_FADV_DONTNEED` so the
system returns to a clean state.

### Cleanup

After any exploit run:

```sh
./dirtyfail --cleanup           # evict /etc/passwd from page cache
sudo ./dirtyfail --cleanup      # also drop_caches (requires root)
```

Or directly:

```sh
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

---

## 7. How DIRTYFAIL detects each CVE

### Copy Fail (active sentinel probe)

Detection actually triggers the primitive against a sentinel file in
`/tmp`:

1. Probe `socket(AF_ALG, SOCK_SEQPACKET, 0)` and `bind` to
   `authencesn(hmac(sha256), cbc(aes))`.
2. Create a 4 KiB sentinel file in `/tmp` and fault its first page
   into the cache.
3. Run the full exploit primitive against it: `sendmsg` AAD with
   `seqno_lo = "PWND"`, splice 32 bytes of the sentinel into the AF_ALG
   op socket, drive `recv` to fire the scratch write.
4. Re-read the sentinel and look for `PWND` anywhere in the first
   page.

Marker found ⇒ vulnerable. Marker absent but page contents differ ⇒
the primitive partially fired (still vulnerable). Page identical ⇒
not vulnerable on this kernel.

### Dirty Frag xfrm-ESP (precondition-based)

Detection is precondition-only — we don't enter a user namespace in
detect mode (it would side-effect networking inside that namespace).
We check:

* kernel version within affected window
* `esp4` / `esp6` currently loaded or autoloadable
* unprivileged user namespace creation succeeds (probed via fork →
  child `unshare(CLONE_NEWUSER)`)

All three present ⇒ VULNERABLE.

### Dirty Frag RxRPC (precondition-based)

* `rxrpc` in `/proc/modules` or autoloadable
* `socket(AF_RXRPC, SOCK_DGRAM, 0)` succeeds

Either ⇒ VULNERABLE.

---

## 8. How DIRTYFAIL exploits each CVE

### Copy Fail exploit (`copyfail.c`)

Single 4-byte STORE through `algif_aead`:

```
                                          [/etc/passwd page cache]
 user  ──sendmsg(AAD = SPI||"0000")──▶ AF_ALG op
       ──splice(passwd_fd, 32B)──────▶ AF_ALG op (in-place dst SGL)
       ──recv()─────────────────────▶ kernel runs authencesn_decrypt
                                        scratch write: "0000" → uid_off
                                        EBADMSG returned to user (we ignore)
 user  ──open(passwd, RDONLY)─read──▶ "kara:x:0000:1000:..."   ◄─ page cache
 user  ──execlp("su", "kara")──────▶ PAM ✓ on /etc/shadow → setuid(0)
                                       ─────► root shell
```

### Dirty Frag xfrm-ESP exploit (`dirtyfrag_esp.c`)

Same end-state as Copy Fail, reached through `xfrm_input` instead of
`algif_aead`:

```
                                          [/etc/passwd page cache]
 unshare(USER|NET); setup uid_map; ifup lo
 NETLINK_XFRM ─NEWSA(seq_hi="0000", encap=ESPINUDP/4500)─▶ kernel
 udp_recv  bind 127.0.0.1:4500, UDP_ENCAP_ESPINUDP
 udp_send  connect 127.0.0.1:4500
 vmsplice  ESP wire header (24B) ─▶ pipe
 splice    /etc/passwd@uid_off (16B) ─▶ pipe
 splice    pipe (40B) ─▶ udp_send
 udp loopback ─▶ udp_recv (UDP_ENCAP) ─▶ xfrm_input ─▶ esp_input
   skb has frags, no frag_list ─▶ goto skip_cow      (THE BUG)
   crypto_authenc_esn_decrypt:
     scratch_write(seq_hi="0000" → page_addr+uid_off)  ◄─ 4-byte STORE
   AEAD auth fails (EBADMSG) — but the STORE is permanent
 page-cache copy of /etc/passwd now reports uid 0 for the user
```

Then exit the namespace, `execlp("su", user)` from the parent — same
final step as Copy Fail.

### Dirty Frag RxRPC exploit

Out of scope for DIRTYFAIL. Use `V4bel/dirtyfrag::exp.c`.

---

## 9. Mitigations

### Copy Fail (CVE-2026-31431)

1. **Apply the patch.** Mainline `a664bf3d`; backports landed on the
   6.12 / 6.17 / 6.18 stable lines.
2. **Interim**: blacklist `algif_aead`:
   ```sh
   echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/copyfail.conf
   sudo rmmod algif_aead 2>/dev/null
   ```
   ⚠ Note: this **does not** mitigate Dirty Frag. The xfrm-ESP path
   reaches the same authencesn primitive without going through
   algif_aead.

### Dirty Frag xfrm-ESP (CVE-2026-43284)

1. **Apply the patch.** Mainline `f4c50a4034e6` (merged 2026-05-07).
   Distro backports rolling out as of 2026-05-08.
2. **Interim**: blacklist `esp4` and `esp6`:
   ```sh
   sudo tee /etc/modprobe.d/dirtyfrag-esp.conf <<'EOF'
   install esp4 /bin/false
   install esp6 /bin/false
   EOF
   sudo rmmod esp4 esp6 2>/dev/null
   sudo sysctl vm.drop_caches=3
   ```
   ⚠ This breaks IPsec / strongSwan / libreswan VPNs.
3. **Defense in depth**: disallow unprivileged user namespaces.
   Ubuntu does this by default via AppArmor; on other distros:
   ```sh
   sudo sysctl -w kernel.unprivileged_userns_clone=0
   ```

### Dirty Frag RxRPC (CVE-2026-43500)

1. **No upstream patch yet.** Researcher patch on lkml; not merged at
   time of writing (2026-05-08).
2. **Interim**: blacklist `rxrpc`:
   ```sh
   sudo tee /etc/modprobe.d/dirtyfrag-rxrpc.conf <<'EOF'
   install rxrpc /bin/false
   EOF
   sudo rmmod rxrpc 2>/dev/null
   sudo sysctl vm.drop_caches=3
   ```
   ⚠ This breaks AFS distributed file system clients. Most servers
   don't need rxrpc.

### Combined one-liner (all three)

```sh
sudo sh -c '
cat > /etc/modprobe.d/dirtyfail.conf <<EOF
install algif_aead /bin/false
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF
rmmod algif_aead esp4 esp6 rxrpc 2>/dev/null
sysctl vm.drop_caches=3
'
```

---

## 10. Ethics & disclosure

DIRTYFAIL is a research tool. The vulnerabilities it covers are
**already publicly disclosed** with weaponized PoCs in the wild
(see [Credits](#11-credits)) — DIRTYFAIL adds detection coverage,
unified documentation, and a gentler PoC variant (UID-flip vs ELF
overwrite of `/usr/bin/su`).

* **Do not run `--exploit-*` modes on systems you do not own or are
  not explicitly authorized to test.** Page-cache modifications are
  reversible with `drop_caches`, but they are still privilege
  escalation while they persist.
* **Do not deploy DIRTYFAIL as a "scanner" against third-party
  infrastructure** without written authorization. The detection mode
  is non-modifying for system files but does open a sentinel file in
  `/tmp` and exercise the kernel crypto API.
* If you find a vulnerable system in the wild, follow responsible
  disclosure to the operator, not the public.

---

## 11. Credits

DIRTYFAIL is original code, but the techniques it implements were
developed by the researchers below. Read their primary sources before
deploying this tool — they are the canonical references.

| Source | Researcher | Contribution |
|--------|------------|--------------|
| <https://copy.fail/> | Anonymous | Original Copy Fail disclosure |
| <https://github.com/Smarttfoxx/copyfail> | Smarttfoxx | C PoC (shellcode-in-`su` variant) |
| <https://github.com/rootsecdev/cve_2026_31431> | rootsecdev | Python detector + UID-flip PoC; the ergonomics of DIRTYFAIL's `--exploit-copyfail` mode follow this approach. |
| <https://github.com/V4bel/dirtyfrag> | Hyunwoo Kim ([@v4bel](https://x.com/v4bel)) | Dirty Frag discovery, full chain PoC, kernel patches |
| <https://www.bleepingcomputer.com/news/security/new-linux-dirty-frag-zero-day-with-poc-exploit-gives-root-privileges/> | BleepingComputer | Public reporting |

Patch authors:

* `f4c50a4034e6` (Dirty Frag xfrm-ESP) — based on Hyunwoo Kim's v1
  patch, with the merged shared-frag approach by Kuan-Ting Chen.
* RxRPC patch — Hyunwoo Kim, pending merge.

---

## License

MIT. See [LICENSE](LICENSE).

---

## Contact

Open an issue on this repository, or reach out at the address listed
in the commit history. For coordinated disclosure of related issues,
contact the upstream researchers above directly.
