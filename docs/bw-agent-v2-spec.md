# bw-agent v2

**Server-assisted PIN unlock for the Bitwarden browser extension**

Implementation specification · v2.0 · draft

---

## Contents

1. [Overview](#1-overview)
2. [Threat model](#2-threat-model)
3. [Architecture](#3-architecture)
4. [Cryptographic construction](#4-cryptographic-construction)
5. [Wire protocol](#5-wire-protocol)
6. [Budget enforcement and revocation](#6-budget-enforcement-and-revocation)
7. [Storage](#7-storage)
8. [Changes to the existing codebase](#8-changes-to-the-existing-codebase)
9. [Implementation notes](#9-implementation-notes)
10. [Testing](#10-testing)
11. [Deployment](#11-deployment)
12. [Build order](#12-build-order)
· [Appendix A — Notation](#appendix-a--notation)
· [Appendix B — Rejected alternatives](#appendix-b--rejected-alternatives)
· [Appendix C — Deferred features](#appendix-c--deferred-features)

---

## 1. Overview

`bw-agent` replaces the Bitwarden desktop application as the native-messaging host for the browser extension's biometric-unlock feature, substituting a short PIN for the biometric. A self-hosted server participates in each unlock so that PIN guesses can be counted.

### 1.1 The problem

A 6–8 character PIN carries 20–50 bits of entropy. In the naive design the encrypted blob on disk contains everything needed to verify a guess except the PIN, so an attacker who obtains the file enumerates candidates locally at whatever rate their hardware allows. Hardening the KDF only changes the cost per guess, which is a losing game; hardware sealing relocates the secret without adding entropy.

The only defence that scales is limiting the **number** of guesses. That requires a counting party the attacker does not control, and a guarantee that a guess cannot be checked without contacting it.

### 1.2 The design

Three mechanisms:

| Mechanism | Purpose |
|---|---|
| **Oblivious PRF** | A guess is uncheckable without a live server round trip. Eliminates offline attack. |
| **Budget enforcement** | Guesses are metered per device. Bounds online attack. |
| **Revocation** | Server destroys `k_i`; that device's blob becomes permanently undecryptable. |

The server never learns the PIN, never sees the vault key, and cannot decrypt anything alone.

### 1.3 Universal fallback

Every failure path — server unreachable, device revoked, budget exhausted, database lost — degrades to logging in with the Bitwarden master password. No vault data is ever at risk. This is what makes it safe to set aggressive limits and to make revocation irreversible.

### 1.4 What the master password is *not* used for

The master password appears exactly once, during enrollment, to obtain the user key through the normal Bitwarden login flow. It is then discarded. No master key material is stored, transmitted, or derivable anywhere in this protocol.

---

## 2. Threat model

### 2.1 In scope

| # | Adversary | Capability | Requirement |
|---|---|---|---|
| T1 | **Blob exfiltration** | Obtains `blob` via backup, sync client, cloud snapshot, discarded disk | Gains nothing. Cannot check a single guess. |
| T2 | **Online guessing** | Has blob and device, can reach the server | ≤48 guesses/day, hard lifetime ceiling, alerting |
| T3 | **Server compromise** | Root on the OPRF server, all `k_i`, all logs | No vault access. PIN still scrypt-hardened. |
| T4 | **Network adversary** | Passive or active on the tailnet | Learns nothing. Cannot replay. |
| T5 | **Local unprivileged process** | Different unix user on the client | Cannot reach the agent socket |
| T6 | **Device theft, powered off** | Has the disk | FDE covers it; blob is inert regardless |

### 2.2 Out of scope

**Malware running as the user.** It keylogs the PIN, reads `identity.key`, and opens a legitimate session. Budget enforcement is the only residual defence and it is not sufficient. No design at this layer fixes this, and the specification does not pretend otherwise.

**Compelled disclosure.** Key-disclosure regimes attach penalties to failure-to-decrypt. Cryptography does not answer this.

**Malicious server operator.** You run the server. If you do not, do not use this.

### 2.3 Trust boundary

| Property | Guaranteed by |
|---|---|
| Server never learns the PIN | Mathematics — blinding by a uniform random scalar is information-theoretic |
| Server never sees the user key | Never transmitted |
| Server alone cannot decrypt | Holds `k_i` only; lacks the blob |
| Compromised server gains nothing retroactively | Logged queries are uniformly random points |
| **Server counts guesses honestly** | **Trust.** Policy, not mathematics. |
| **Revocation deletes `k_i`** | **Trust.** |

Rate limiting is irreducibly a trusted operation — nothing compels a party to count. The mitigations are to keep that trusted surface tiny (§6.1) and to note that a server which lies about counting still holds nothing that decrypts anything, and the attacker still needs the blob.

---

## 3. Architecture

```
┌─────────────── client host ────────────────┐
│                                            │
│  browser extension                         │
│        │  native messaging (stdio)         │
│        ▼                                   │
│    bw-proxy                                │
│        │  unix socket, 0600                │
│        ▼                                   │
│    bw-agent ──── askpass (PIN prompt)      │
│        │                                   │
└────────┼───────────────────────────────────┘
         │  Noise_IK over tailnet
         ▼
    bw-keyd ──── SQLite (k_i, budgets)
         ▲
    bw-keyctl (admin, local only)
```

| Binary | Role |
|---|---|
| `bw-proxy` | Native-messaging host registered as `com.8bit.bitwarden`. Relays framed stdio to the agent socket. Unchanged from v1. |
| `bw-agent` | Long-running user daemon. Speaks the extension's unlock protocol, prompts for the PIN, performs the OPRF exchange, decrypts the blob. |
| `bw-keyd` | Server. Holds per-device `k_i`, enforces budgets, answers blinded queries. |
| `bw-keyctl` | Local admin CLI. Enrollment tokens, revocation, counter reset. |

---

## 4. Cryptographic construction

### 4.1 Key derivation

```
K = HKDF-SHA256(
      ikm  = scrypt(PIN, salt, N=2^17, r=8, p=1, dkLen=32) ‖ oprf_output,
      salt = salt,
      info = "bw-agent/v2/blob",
      L    = 32
    )
```

Two independent inputs, each covering the other's failure mode:

- **`oprf_output`** (64 B, requires the server) makes offline guessing impossible. The primary defence.
- **`scrypt`** (32 B, purely local, 128 MiB) is the backstop for T3. If `k_i` ever leaks, an attacker with the blob can compute `oprf_output` themselves; without scrypt the remaining grind is a millisecond-per-guess HKDF. With it they pay 128 MiB and roughly half a second per candidate.

Neither input alone is sufficient, and neither is redundant.

### 4.2 Oblivious PRF

**Ciphersuite:** RFC 9497 OPRF, `ristretto255-SHA512`, mode `0x00` (base OPRF).

Verifiable mode is not used: an AEAD failure already detects a server returning incorrect evaluations, and the client authenticates by device identity so it has no anonymity to protect.

```
contextString = "OPRFV1-" ‖ I2OSP(0x00, 1) ‖ "-ristretto255-SHA512"
```

**Client — Blind**

```
inputElement   = HashToGroup(PIN)
blind          ←$ nonzero scalar mod ℓ
blindedElement = blind · inputElement          → 32 bytes, sent
```

`HashToGroup` is `hash_to_ristretto255` (RFC 9380): `expand_message_xmd(SHA-512)` with

```
DST = "HashToGroup-" ‖ contextString
```

yielding 64 uniform bytes, then `RistrettoPoint::from_uniform_bytes`.

> **Implementation warning.** `curve25519-dalek`'s `RistrettoPoint::hash_from_bytes::<Sha512>()` is **not** RFC 9380 `hash_to_ristretto255` — it omits the domain separation tag. Using it yields a system that works perfectly and silently disagrees with the RFC test vectors, which is exactly the failure this specification cannot tolerate. Prefer the `voprf` crate (§9.1).

**Server — Evaluate**

```
evaluatedElement = k_i · blindedElement        → 32 bytes, returned
```

**Client — Finalize**

```
N            = blind⁻¹ · evaluatedElement
serialized   = SerializeElement(N)             // 32 bytes, canonical encoding
oprf_output  = SHA-512( I2OSP(len(PIN), 2) ‖ PIN
                      ‖ I2OSP(32, 2) ‖ serialized
                      ‖ "Finalize" )           // 64 bytes
```

**Why the server learns nothing.** `blind` is uniform over the nonzero scalars, so `blindedElement` is uniform over the group *independently of the PIN*. The transmitted value carries zero bits of information about the input — not "computationally hidden," literally none. A server that logs every request forever and is later fully compromised gains nothing from those logs.

**Why the client cannot proceed alone.** Computing `oprf_output` requires `k_i`. Recovering `k_i` from an evaluation is the discrete logarithm problem. Each round trip yields exactly one candidate evaluation; there is no batching, compression, or amortisation across guesses. **Counting requests is therefore counting guesses**, which is the entire point of the construction.

### 4.3 Blob format

124 bytes, fixed size, no header.

```
offset  size  field
------  ----  -----------------------------------------------
0       32    salt        random at enrollment, stable for life
32      12    nonce       fresh random on every write
44      80    ct ‖ tag    AES-256-GCM, 80 B plaintext + 16 B tag
```

Plaintext (80 bytes):

```
offset  size  field
------  ----  -----------------------------------------------
0       64    user_key    Bitwarden user key (32 enc ‖ 32 MAC)
64      16    padding     zero on write, ignored on read
```

**AEAD:** AES-256-GCM with key `K`, the stored nonce, and **AAD = `salt`**.

No version byte and no magic value. If a format revision is ever needed, it is signalled by the file's length, which is checked before parsing.

Written atomically: temporary file in the same directory → `fsync` → `rename` → `fsync` on the directory.

---

## 5. Wire protocol

### 5.1 Transport

**Noise_IK_25519_ChaChaPoly_BLAKE2s**, via the `snow` crate.

`IK` is the correct pattern here: the initiator (client) knows the responder's (server's) static public key from enrollment, and transmits its own static key inside the first message, allowing the server to identify the device and apply per-device policy immediately.

| Property | Rule |
|---|---|
| Client identity | `identity.key`, X25519 static keypair generated at enrollment |
| Server identity | Static public key pinned in `device.toml`. A mismatch is a **hard failure** — never prompt to accept |
| Binding | Server binds to the tailnet interface only. Never `0.0.0.0` |
| Sessions | Fresh handshake per request. No resumption, no long-lived sessions |
| Replay | Handled by Noise; no application-layer nonce needed |
| Framing | 4-byte **big-endian** length prefix, then the Noise message |

> The browser native-messaging path uses a **native-endian** prefix, as required by the Chrome and Firefox specifications. `proxy.rs` keeps `to_ne_bytes`; the network path uses `to_be_bytes`. Do not unify these.

### 5.2 Messages

JSON bodies inside the Noise session. The transport provides authentication, integrity, and replay protection; no application-layer signatures are required.

**Request**

```json
{ "v": 2, "type": "eval", "blinded": "<base64, 32 bytes>" }
```

There is deliberately no `device_id` field. Identity comes from the authenticated Noise static key; a client-supplied identifier would only create the possibility of a mismatch between claimed and authenticated identity.

**Responses**

```json
{ "v": 2, "type": "ok",        "evaluated": "<base64, 32 bytes>", "tokens_left": 4 }
{ "v": 2, "type": "throttled", "retry_after_s": 1200 }
{ "v": 2, "type": "denied" }
```

> **Normative.** `denied` is returned for revoked devices, unknown static keys, and pending enrollments alike, with identical timing. Distinguishing them creates a device-enumeration oracle.

**There is no success acknowledgement.** See §6.3.

### 5.3 Unlock flow

```
 1. extension → proxy → agent     unlockWithBiometricsForUser
 2. agent                         prompt PIN via askpass
 3. agent                         blindedElement = Blind(PIN)
 4. agent → server                eval{blinded}
 5. server                        consume budget, COMMIT + fsync
 6. server                        evaluatedElement = k_i · blindedElement
 7. server → agent                ok{evaluated}
 8. agent                         oprf_output = Finalize(...)
 9. agent                         K = HKDF(scrypt(PIN) ‖ oprf_output)
10. agent                         decrypt blob → user_key
11. agent → extension             userKeyB64 over the existing EncString channel
12. agent                         zeroize all intermediates
```

Steps 1–2 and 11 are the existing v1 code path and are unchanged.

Note that step 9's scrypt costs ~0.5 s. Perform it concurrently with steps 4–7 to hide the latency, but **do not** cache the result across attempts.

### 5.4 Enrollment

```
1. operator     bw-keyctl enroll --label "laptop"
                → token: 32 random bytes, base32, 15-minute expiry, single use

2. client       bw-agent enroll --server <host:port> --token <token>
                → device_id     16 random bytes
                → identity.key  X25519 static keypair

3. client → server    enroll{token, static_pub, device_id, label}
                      over Noise_NK — server static known from the token blob,
                      client static not yet trusted

4. server       validate token and expiry, generate k_i ←$ scalar,
                set state='active', invalidate token

5. client       master-password login via existing auth.rs → user_key

6. client       prompt PIN (twice, confirmed)
                salt ←$ 32 bytes
                OPRF round trip → oprf_output
                K = HKDF(scrypt(PIN, salt) ‖ oprf_output)
                write blob atomically

7. client       zeroize user_key, master password, master key, PIN
```

Step 5 is the only point at which the master password exists in this system.

### 5.5 Administration

```
bw-keyctl list                         device_id, label, state, last_seen, budget
bw-keyctl enroll --label <name>        → one-time token
bw-keyctl revoke <device_id>           irreversible
bw-keyctl reset  <device_id>           clear lifetime counter
bw-keyctl panic                        revoke all devices
```

Rotation is revoke followed by re-enrollment.

---

## 6. Budget enforcement and revocation

This is the load-bearing component. Everything else is plumbing around it.

### 6.1 Design constraint

The server **cannot distinguish a successful unlock from a failed one** — it never sees the user key or the blob. Two consequences follow, and both have caused incorrect designs:

1. **The budget cannot reset on success.** It can only refill with elapsed time or by operator action.
2. **The budget must exceed legitimate usage**, since the server counts your unlocks alongside an attacker's. Your usage therefore sets the attacker's floor rate. No parameter tuning escapes this; only PIN length does.

### 6.2 Parameters

| Layer | Setting | Bound |
|---|---|---|
| **Token bucket** | capacity 6, +1 per 1800 s | 48 guesses/day |
| **Lifetime counter** | monotonic, ceiling 15 000 → auto-revoke | total exposure |
| **Alerting** | > 30 in 24 h, or > 200 in 7 d | ends a grind within days |

Annual success probability against the bucket:

| PIN | Probability/year |
|---|---|
| 6 digits | 1.75 % |
| 7 digits | 0.18 % |
| 8 digits | **0.018 %** |

**Recommendation: 8 characters.** Each additional character multiplies every figure above by 10 (digits) or ~70 (alphanumeric). No protocol change in this document comes close to that leverage.

If the budget feels tight in practice, lengthen the PIN or raise the browser extension's vault-timeout setting — **never raise the ceiling**. Moving the timeout from 15 to 60 minutes cuts unlock frequency roughly fourfold at no security cost, because an already-unlocked extension is outside what this system protects.

Alerting is the layer that actually terminates an attack; the counters merely bound the damage while it fires. Route alerts somewhere readable while travelling, and test that path.

### 6.3 Algorithm

```
elapsed = max(0, now - tokens_ts)              ← clamp; clocks move backwards
tokens  = min(6.0, tokens + elapsed / 1800.0)
tokens_ts = now

if state != 'active':                          → denied
if lifetime >= 15000:  revoke(device);         → denied
if tokens < 1.0:
    retry_after = ceil((1.0 - tokens) * 1800)
    UPDATE tokens, tokens_ts; COMMIT           ← lifetime NOT incremented
                                               → throttled

tokens   -= 1.0
lifetime += 1
UPDATE tokens, tokens_ts, lifetime, last_seen
COMMIT + fsync                                 ← BEFORE evaluating

evaluatedElement = k_i · blindedElement        → ok
```

### 6.4 Invariants

These three are the entire security argument for §6. A review of this code asks only these questions.

1. **Fail-closed.** Both counters persist, with `fsync`, *before* the evaluation is performed. A crash, power loss, or kill signal must cost an attempt, never grant one. Do not batch, defer, or cache these writes — a few dozen `fsync` calls per day is nothing, and every optimisation here silently removes the only thing protecting the PIN.

2. **No client-controlled budget.** The bucket moves only with elapsed time; `lifetime` moves only forward, or backward via `bw-keyctl reset` from an operator shell. Nothing arriving on the wire can increase either budget.

3. **Throttled requests do not count.** A request rejected by the bucket must not increment `lifetime`. Otherwise an attacker who cannot pass the bucket can still exhaust the ceiling and destroy the device — turning the backstop into a denial-of-service lever.

### 6.5 Revocation

```sql
BEGIN;
UPDATE devices SET oprf_key = NULL, state = 'revoked', revoked_at = ?
  WHERE device_id = ?;
COMMIT;
VACUUM;
```

With `k_i` destroyed, `oprf_output` is uncomputable by anyone — including the operator, and including an attacker who compromises the server later. That device's blob is ciphertext under a key that no longer exists. Other devices are entirely unaffected.

The row is retained so the `device_id` can never be reused; enrollment against a revoked ID is refused.

**On deletion durability:** without a TPM, `VACUUM` does not guarantee erasure from SSD spare blocks. This is accepted. A forensically recovered `k_i` is worthless without the victim's blob *and* their PIN, and an attacker holding the blob has the device and better options available.

---

## 7. Storage

### 7.1 Client

```
$XDG_STATE_HOME/bw-agent/        (mode 0700, fallback $HOME/.local/state)
  identity.key    32 B   Noise X25519 static private key      0600
  blob           124 B   §4.3                                 0600
  device.toml      —     device_id, server address, server pubkey
```

> **Normative: not `~/.cache`.** Cache directories are precisely what naive backup and sync tools replicate, which is threat T1 verbatim.

> **Normative: one path function.** `bw-agent` and `bw-proxy` must resolve the socket path through the same shared function. The v1 code had `ipc.rs` honouring `XDG_CACHE_HOME` while `proxy.rs` hardcoded `$HOME/.cache`, so setting that variable silently broke the pair with no error.

Document backup exclusion for Restic, Borg, and rsync in the README. On macOS, set `com.apple.metadata:com_apple_backup_excludeItem` on the directory.

### 7.2 Server

One SQLite table. WAL mode. FDE volume.

```sql
CREATE TABLE devices (
    device_id    BLOB PRIMARY KEY,          -- 16 bytes
    static_pub   BLOB UNIQUE,               -- 32 bytes; NULL until enrolled
    oprf_key     BLOB,                      -- 32 bytes; NULL once revoked
    enroll_hash  BLOB,                      -- SHA-256(token); NULL after use
    enroll_exp   INTEGER,
    label        TEXT,
    state        TEXT NOT NULL,             -- 'pending' | 'active' | 'revoked'
    tokens       REAL    NOT NULL DEFAULT 6.0,
    tokens_ts    INTEGER NOT NULL,
    lifetime     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    last_seen    INTEGER,
    revoked_at   INTEGER
);

CREATE UNIQUE INDEX idx_devices_static_pub ON devices(static_pub);
```

Enrollment tokens and revocation tombstones are represented as states within this table rather than as separate tables.

### 7.3 Backup policy

| Item | Back up? |
|---|---|
| `device.toml` | Optional; convenience only |
| `blob`, `identity.key` | **No.** Losing them costs a 30-second re-enrollment; backing them up recreates T1. |
| `devices.db` | Only if you accept that a restore resurrects revoked devices. Safer not to, and to re-enroll after a rebuild. |

---

## 8. Changes to the existing codebase

### 8.1 Module disposition

| Module | Action |
|---|---|
| `auth.rs` | **Keep.** Bitwarden login, PBKDF2/Argon2id, `stretch()` are correct. Used only at enrollment. |
| `crypto.rs` | **Keep.** EncString type-2 is still needed for the extension channel. |
| `proxy.rs` | **Keep**, with the shared path function from §7.1. |
| `askpass.rs` | **Keep.** PIN prompt unchanged. |
| `log.rs` | **Keep**, but see bug 1 below. |
| `storage/pin.rs` | **Replace** with the §4.3 blob format. |
| `storage/tpm2.rs` | **Delete.** No TPM in the deployment. |
| `ipc.rs` | **Rewrite** for concurrency and peer verification. |
| `bridge.rs` | **Modify:** session handling, and the OPRF call replacing local unseal. |
| *new* `oprf.rs` | Client side of §4.2. |
| *new* `net.rs` | Noise transport, §5.1. |
| *new* `bw-keyd` | Server. |

### 8.2 Bugs to fix first

These exist in v1 and several become materially worse once a network is involved. Phase 0 in §12.

1. **`bridge.rs::handshake` calls `log::fatal` on a malformed public key**, and again on RSA failure. Any local process can kill the daemon with one bad message. Return `invalidateEncryption` instead.
2. **`ipc.rs::serve` handles one connection at a time**, synchronously — `for stream in listener.incoming()` calling `handle_conn` inline. One stuck client blocks every other.
3. **No peer credential check** on the local socket. Add `SO_PEERCRED` (Linux) or `getpeereid` (macOS); reject any uid other than the daemon's own.
4. **Socket permissions are set after `bind()`**, leaving a window at the default umask. Call `umask(0o177)` before binding instead.
5. **`sessions: HashMap` grows unboundedly** with distinct client-supplied `appId` values. Cap it, and key sessions on verified peer identity rather than on `appId`.
6. **`find_key()` returns the first `readdir` entry**, silently selecting an arbitrary account on multi-account installs.
7. **`storage/tpm2.rs` "wipes" its temp file with `File::create`**, which truncates first — the plaintext user key's original blocks are never overwritten. Moot once the file is deleted, but do not carry the pattern elsewhere.

### 8.3 Extension-facing protocol

Unchanged. The RSA-OAEP-SHA1 handshake and EncString channel are dictated by the Bitwarden extension and are not ours to modify. Note that this protocol provides no cryptographic binding between the extension and the agent — a limitation inherited from Bitwarden's own design, mitigated here by the peer credential check in 8.2(3).

---

## 9. Implementation notes

### 9.1 Dependencies

| Purpose | Crate | Note |
|---|---|---|
| OPRF | `voprf` | **Strongly preferred over hand-rolling** — see §4.2 |
| Curve, if hand-rolling | `curve25519-dalek` | `expand_message_xmd` + `from_uniform_bytes`, never `hash_from_bytes` |
| Transport | `snow` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` |
| AEAD | `aes-gcm` | Constant-time tag comparison |
| KDF | `scrypt`, `hkdf` | |
| Memory | `zeroize` | `Zeroizing<T>` |
| Server DB | `rusqlite` | Bundled SQLite, WAL |
| Randomness | `getrandom` | Never a userspace PRNG for key material |

### 9.2 Zeroization

Wrap in `Zeroizing<T>` and drop as early as possible: the PIN (from `askpass` through `Blind` and `scrypt`), the `blind` scalar, `oprf_output`, the scrypt output, `K`, `user_key`, and — during enrollment only — the master password and master key.

Known unclosable holes, worth knowing rather than papering over: AES-GCM internal buffers, `serde_json::to_vec` output, base64 `String` allocations, and kernel socket buffers. The v1 `KEY_PLACEHOLDER` technique (keeping the key out of `serde_json::Value`) is worth retaining for the JSON path; it helps but does not close these.

### 9.3 Error handling

**Never distinguish**, in message or in timing:

- Wrong PIN · corrupted blob · AEAD failure → one generic failure
- Revoked · unknown · pending device → `denied`

**Do distinguish clearly**, since these are operational rather than security-relevant:

- Server unreachable → "server unreachable — unlock with your master password"
- Throttled → "too many attempts, retry in N minutes"

### 9.4 Concurrency

`bw-agent` handles one unlock at a time by nature (a single PIN prompt), but must not block its socket while doing so. Accept connections on a thread pool; serialise only the prompt.

`bw-keyd` must serialise budget updates per device. A single SQLite writer with `BEGIN IMMEDIATE` is sufficient and simplest — throughput requirements are a few dozen requests per day.

---

## 10. Testing

### 10.1 Required

| Test | Rationale |
|---|---|
| **RFC 9497 test vectors**, `ristretto255-SHA512`, mode `0x00` | A blinding or DST error is silent: the system works end to end and the offline protection is simply absent. Non-negotiable, and must pass before any real vault is enrolled. |
| Blob round-trip: write → read → compare `user_key` | Corruption here means a lost vault |
| EncString round-trip against a captured desktop-app response | Extension compatibility |
| `stretch()` against Bitwarden's `stretchKey` | Enrollment correctness |
| 7 rapid requests → the 7th is throttled | Core property |
| `kill -9` mid-evaluation → attempt still consumed | Invariant 1 |
| No wire message increases `tokens` or `lifetime` | Invariant 2 |
| Throttled request leaves `lifetime` unchanged | Invariant 3 |
| Lifetime ceiling reached → device auto-revoked, not merely throttled | Backstop fires |
| Revoked vs. unknown device → identical response and timing | No enumeration oracle |
| Clock stepped backwards → no over-refill | `elapsed` clamp |

### 10.2 Failure injection

- Server offline mid-unlock → clean error, no partial state, no key material leaked
- Corrupted blob → generic failure, no panic
- Wrong server static key → hard failure, no prompt to accept
- Replayed `eval` message → rejected by Noise
- Malformed extension handshake → `invalidateEncryption`, daemon survives (regression test for bug 1)

---

## 11. Deployment

### 11.1 Client unit

User unit at `~/.config/systemd/user/bw-agent.service`:

```ini
[Unit]
Description=bw-agent
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/bw-agent
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=%S/bw-agent
MemoryDenyWriteExecute=true

[Install]
WantedBy=default.target
```

### 11.2 Server unit

```ini
[Service]
User=bwkey
ExecStart=/usr/local/bin/bw-keyd
StateDirectory=bw-key
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
MemoryDenyWriteExecute=true
```

### 11.3 Co-hosting with Vaultwarden

Acceptable, but it places a small hard target behind a large soft one. Required mitigations: separate unix user, separate database, Vaultwarden containerised with no filesystem path to the OPRF database, and `bw-keyd` bound to the tailnet interface only.

Keeping Vaultwarden itself tailnet-only does more for overall posture than most of the cryptography in this document.

### 11.4 Native messaging manifest

The v1 `docs/com.8bit.bitwarden.json` is incomplete: it contains a `%user%` placeholder, a macOS-only path, and only Firefox's `allowed_extensions` — Chrome requires `allowed_origins` with the extension ID. Restore a `make install-nm` target (removed in `aaa0f5b`) that generates the manifest for the running platform and browser.

### 11.5 Monitoring

Log per request: timestamp, `device_id`, outcome, `tokens` remaining, `lifetime`. **Never log `blindedElement`** — harmless in principle, but there is no reason to retain it.

Alert on: >30 consumed in 24 h or >200 in 7 d for any device; `lifetime` crossing 80 % of ceiling; any `denied`; any enrollment token use.

### 11.6 Key rotation

Changing the Bitwarden master password does **not** invalidate a compromised user key — it re-wraps the same key under a new master key. If a user key is believed compromised, use *Rotate account encryption key* in the Vaultwarden web vault, which re-encrypts the entire vault, then re-enroll every device. Know this before you need it.

---

## 12. Build order

| Phase | Deliverable | Standalone value |
|---|---|---|
| **0** | §8.2 bug fixes; delete `tpm2.rs` | v1 stops being trivially DoS-able |
| **1** | §4.3 blob replaces `pin.rs` (scrypt only, no server yet) | Cleaner format; still fully local and usable |
| **2** | Noise transport, enrollment, pinned identities, `bw-keyd` skeleton | Authenticated channel |
| **3** | **OPRF both ends + §6 budget enforcement** | **The actual security property** |
| **4** | `bw-keyctl`, alerting, manifest install target | Operational completeness |

Phases 0 and 1 require no server and are worth doing regardless. Phase 2 carries forward unchanged into phase 3 — only the key derivation changes.

Estimated new code: ~350 lines client, ~250 lines server.

> **Before phase 3 touches a real vault:** pass the RFC 9497 vectors (§10.1), and have the OPRF and transport reviewed by someone else. A subtle error in blinding or in the fail-closed path is silent and total — everything continues to work, and the protection simply is not there.

---

## Appendix A — Notation

| Symbol | Meaning |
|---|---|
| `k_i` | Per-device OPRF key; ristretto255 scalar; server-only |
| `K` | AES-256-GCM blob key; derived per unlock; never persisted |
| `user_key` | Bitwarden 64-byte user key (32 enc ‖ 32 MAC) |
| `ℓ` | Order of the ristretto255 group |
| `‖` | Concatenation |
| `I2OSP(n, k)` | `n` encoded big-endian in `k` bytes |
| `←$` | Uniform random sampling |
| `·` | Scalar multiplication on the group |

## Appendix B — Rejected alternatives

| Considered | Rejected because |
|---|---|
| Server stores per-device wrapped blobs | Server becomes a vault; one exfiltration re-enables offline grinding for every device |
| TPM2 sealing | No TPM in the deployment; relocates the secret without adding entropy; fails when the hardware does |
| YubiKey HMAC challenge-response | Portable and effective, but loss kills every blob and it provides no revocation. Reasonable *addition* later, not a replacement. |
| `dev_secret` file as a second KDF input | Sits in the same directory with the same permissions as the blob and `identity.key`; no realistic leak separates them. scrypt (§4.1) covers the case that actually matters. |
| Stronger KDF alone (Argon2id, higher scrypt) | Buys hours against a GPU. Not security for 20 bits. |
| Verifiable OPRF (VOPRF) | AEAD failure already detects a lying server; the client has no anonymity to protect |
| Threshold OPRF across two servers | Genuine trust reduction, double the infrastructure. Revisit only if the single server becomes untrusted. |
| Client-sent success acknowledgement to reset the budget | **Broken.** An attacker holding the device forges it after every wrong guess. See §6.1. |
| Offline fallback cache | Moot with Vaultwarden tailnet-only — no tailnet means no vault sync to unlock. Would also reinstate offline grinding and delay revocation. |
| Multi-slot table, duress PINs, decoy vault | See Appendix C |

## Appendix C — Deferred features

These are purely client-side blob-format changes and require no protocol modification. They can be added after the system works.

**Multi-slot table.** Replace the single blob with a fixed 8-slot table, all slots always present and indistinguishable from random, trial-decrypted in constant time. Makes the number of enrolled PINs unanswerable from the file. Note that byte-level indistinguishability is of limited value while the binary, systemd unit, and native-messaging manifest announce the system's presence.

**Duress PINs.** With a slot table, an action byte in each slot's plaintext can trigger self-revocation instead of unlocking, presenting to an observer as a failed unlock. Requires constant-time scanning, otherwise unlock latency reveals which slot matched.

**Decoy vault.** Not achievable with the Bitwarden extension protocol: `unlockWithBiometricsForUser` carries a `userId` and the extension is logged into exactly one account, so returning another account's user key produces a decryption failure rather than a plausible decoy — worse than a clean failure, because it looks like corruption. A real decoy requires a second browser profile logged into a decoy account, provisioned manually. Documentation item, not a protocol feature.

**Push approval.** With multiple devices enrolled, an unlock on one could require approval on another. Larger practical security gain than most of the cryptography above, and inexpensive once the server exists.
