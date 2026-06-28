# KZG SRS (trusted setup) for ZKMist V2

This document explains the **one and only trust root** in the ZKMist V2 system:
the KZG Structured Reference String (SRS) the prover commits against. It covers
why it exists, how a deployer obtains and verifies it, and how each claimant
downloads and verifies it independently — so that **no one has to trust the
deployer**.

> **Status:** the mechanism described here is implemented in
> `cli/src/halo2_prover.rs` (`load_or_download_params`, including the
> `ensure_params_k` exact-k guard) and `cli/src/download.rs`
> (`download_and_verify_to_file`). The **trust root is intentionally left as a
> placeholder** (`KZG_SRS_URL` / `KZG_SRS_SHA256` empty in
> `cli/src/constants.rs`) until the deployer completes the procedure in
> [§2](#2-deployer-obtain-verify-and-pin-the-transcript). The readiness checker
> gates on this (check `[1d/8]`).
>
> **k = 23** (not 24): the secp256k1 `point_add_mixed` optimization (2026)
> halved the witness, so the circuit now needs `2^23 = 8,388,608` rows and the
> pinned SRS file MUST be at **exactly k=23** — see §1.1.

---

## 1. Why an SRS, and why not "trustless"

Halo2-KZG commitments require a Structured Reference String — a list of elliptic
curve points `[G₁, τ·G₁, τ²·G₁, …, τⁿ⁻¹·G₁]` derived from a secret scalar τ
(the "trapdoor" / "toxic waste"). Provers and verifiers use it to make and check
polynomial commitments **without ever knowing τ**. Whoever *does* know τ can
forge proofs, so τ must be generated collaboratively and then destroyed.

There are three trust models:

| Model | Secret τ? | Ceremony? | On-chain cost (per claim) |
|---|---|---|---|
| **Trustless** (halo2-IPA / STARK) | none | none | high (~1–3M+ gas, no precompile) |
| **Universal ceremony** (halo2-KZG + public SRS) | yes, destroyed | once, reused | low (~350–400K gas, `ecPairing`) |
| **Self-generated** (`Params::new`) | yes, **1-of-1** | (you alone) | low, but **forgeable by you** |

ZKMist V2 uses halo2-KZG for cheap per-claim verification (the reason V1's
trustless STARK was abandoned — see `V2_PLAN.md`). The deployer's job is to
ensure the prover loads a **public, universal ceremony SRS** rather than
generating its own, so the trust assumption is *1-of-many-thousands* instead of
*1-of-1*.

> ⚠️ **The previous code generated its own SRS (`Params::new`).** That made every
> proof forgeable by whoever ran it. The loader now refuses to do that in
> production and only permits `Params::new` behind an explicit `ZKMIST_DEV_SRS=1`
> dev gate (flagged by the readiness checker).

### Which ceremony? (the size trap)

The **Ethereum EIP-4844 KZG ceremony** (≈140,000 participants) is the gold
standard of public trust — but it produced only **2¹² = 4,096 G1 points**,
sized for blob verification. ZKMist V2's circuit needs **2²³ = 8,388,608**
points (k=23). The EIP-4844 SRS is therefore **~2,000× too small** and cannot
be used.

The correct source is the **PSE perpetual powers-of-tau** ceremony — a universal,
updatable ceremony sized for halo2 (well beyond 2²³ points), reused by Scroll,
Taiko, Polygon zkEVM, and others. It is still a ceremony (1-of-N honesty on the
PSE participants), but N is large and the transcript is publicly audited.

### 1.1 The file MUST be at exactly k=23 (not “k ≥ 23”)

`halo2_proofs::poly::commitment::Params::read` reads the file’s embedded `k`
**as-is — there is no truncation**, and the prover then allocates a witness
grid of `2^params.k()` rows. Consequences of a wrong-k file:

- `k < 23` → halo2 rejects with `NotEnoughRowsAvailable` (circuit doesn’t fit).
- `k > 23` → `create_proof` still allocates `2^k` rows. A k=26 file would
  allocate **64M rows (~120 GiB RSS)** — the prover OOMs even though the
  circuit only uses 8M. AND the proof verifies against a domain the on-chain
  verifier (which embeds the VK’s `k`) does not expect → proofs fail on-chain.

The prover now enforces this with `ensure_params_k` (a mismatch aborts with a
message naming both k values, the memory multiplier, and this doc) — but the
**pinned file itself must be k=23**, so the deployer’s extraction step (§2.1)
must target exactly k=23.

> ⚠️ **Truncation is not available via the halo2 0.3.x public API.**
> `Params.g_lagrange` is `pub(crate)`, and there is no `truncate`/`downsize`
> method, so a tool **in this repo cannot** downsize a larger halo2 params
> file to k=23. You must either (a) extract directly at k=23 via the ceremony’s
> phase2 tooling (§2.1), or (b) fork halo2 to expose `g_lagrange` and write a
> truncation tool. Option (a) is strongly preferred.

---

## 2. Deployer: obtain, verify, and pin the transcript

This is a **one-time** step, done once before mainnet deployment. After this,
the system is "deploy and forget" — claimants self-serve forever.

### 2.1 Obtain the PSE halo2 params file at k=23

The prover's `Params::<G1Affine>::read` consumes **halo2_proofs 0.3.0's binary
params format** (the same format `Params::write` produces) at **exactly k=23**
(see §1.1 — truncation is not possible via the halo2 0.3.x public API). The PSE
**perpetual powers-of-tau** ceremony (repo:
`privacy-scaling-explorations/perpetualpowersoftau`) publishes a raw MPC
*transcript*, not halo2 params directly. To produce a halo2 params file at k=23
you extract from that transcript using the PSE phase2 / halo2 setup tooling at
the target size:

- **(Preferred) Run the PSE phase2 extraction at k=23.** Use the official PSE
  halo2 setup tooling (the same code path Scroll/Taiko/Polygon use) to derive a
  `params-k23.bin` (halo2 0.3.0 params format, `2^23` G1 points) directly from
  the perpetual-powers-of-tau transcript. This is the only path that avoids
  trusting a third party's conversion AND gives the exact k=23.
- **(Alternative) Download a pre-converted halo2 params file** published by a
  reputable source (PSE or a major halo2 project) at **exactly k=23**. Many
  projects publish at k=21, 22, 25, 26 — **verify the published file's k is
  exactly 23** before pinning; a different k is rejected by `ensure_params_k`.
  If only a larger-k file is available, you must run phase2 extraction yourself
  at k=23 (you cannot truncate it — §1.1).

> ⚠️ **Trust note:** the phase2 extraction is deterministic, so two independent
> parties extracting at k=23 from the same transcript must produce
> byte-identical output. Cross-check your digest against another project's
> k=23 file if one exists.

### 2.2 Independently verify the file

Before pinning anything, confirm the file you have is the genuine PSE SRS **at
k=23**:

1. Re-derive its SHA-256 yourself (do not copy a hash from anywhere — compute it):
   ```bash
   sha256sum params-k23.bin
   ```
2. Cross-reference that digest against the PSE ceremony's published records (the
   ceremony's final accumulated transcript has a publicly committed digest). If
   you ran phase2 extraction yourself, the digest is whatever you produced — the
   trust is in the ceremony transcript, not a hash you were told.
3. Sanity-check the file parses as halo2 params and reports **k=23** (the
   readiness checker's `ensure_params_k` enforces this at runtime; you can also
   confirm via `Params::read` + `params.k()` in a one-off script).

### 2.3 Publish the file

Host the verified file at a stable URL the claimants will download from. Good
options:

- A **GitHub Release asset** on the project repo (immutable once published; same
  model already used for the eligibility list — see `cli/src/download.rs`).
- **IPFS** with the content-addressed CID pinned (the CID *is* the integrity
  check; the SHA-256 in code is the redundant, human-readable pin).

### 2.4 Pin the trust root in the CLI

Set both constants in `cli/src/constants.rs`:

```rust
pub const KZG_SRS_URL: &str =
    "https://github.com/<org>/<repo>/releases/download/<tag>/params-k23.bin";
pub const KZG_SRS_SHA256: &str =
    "<the 64-hex-char SHA-256 you computed in §2.2, lowercase, no 0x>";
```

Then rebuild and confirm the readiness checker passes:

```bash
cargo build --release -p zkmist-cli
cargo run -p zkmist-tools --bin readiness   # [1d/8] must now say ✅ pinned
```

> **Why the hash and not "just trust the URL"?** A GitHub/IPFS URL could be
> repointed. The SHA-256 is content-addressed: a different file hashes
> differently, so even if the URL is hijacked, claimants' clients reject the
> substitute. The deployer *pins* the hash but *cannot change the SRS* after
> claimants have recorded it — and cannot forge proofs regardless, because they
> do not know the PSE ceremony's trapdoor.

---

## 3. Claimant: download, verify, and prove

Each claimant performs this **once** (the file is cached and re-verified on
every run, so a tampered cache is rejected). Nothing here requires trusting the
deployer beyond the published, pinned hash — which is itself a commitment to a
public ceremony the deployer had no part in.

1. **Install** the `zkmist` CLI (see `README.md`).
2. **Run** `zkmist prove --key-file <your-key> <eligibility args>`.
   - On first run the CLI streams the pinned SRS file to
     `~/.zkmist/cache/v2_params_k23.bin`, showing a progress bar, and verifies
     its SHA-256 against the value compiled into the binary. **A mismatch
     aborts before any proof is created.** This is a few hundred MB and happens
     once. The file’s k (23) is also asserted before use.
   - On every subsequent run the cached file is **re-hashed** and compared to
     the pinned value before use — so a tampered local cache is also rejected.
3. The CLI creates the Halo2-KZG proof, **verifies it locally** against the
   pinned SRS, and writes the proof file.
4. Submit the proof to the `ZKMAirdrop` contract (`zkmist submit`), which
   verifies it on-chain via `Halo2Verifier` (a single `ecPairing` check).

**What the claimant is trusting:** that *at least one* of the many PSE ceremony
participants was honest and destroyed their contribution. They are **not**
trusting the deployer (who only pinned a public hash), the download host (the
SHA-256 catches substitution), or their own cache (re-verified each run).

---

## 4. Local development / testing without the real SRS

For local dev and CI you do not need the multi-hundred-MB transcript. Set:

```bash
export ZKMIST_DEV_SRS=1
```

The prover then generates a **random, self-contained SRS** via `Params::new`
and caches it locally. **Never use proofs produced this way on mainnet** — the
operator of the dev SRS knows its trapdoor and can forge proofs. This path is
clearly warned at runtime and flagged by the readiness checker (`[1c/8]` would
flip to failing only if the dev gate were removed; `[1d/8]` fails until the real
hash is pinned, which is the real gate).

Note: at k=23, `Params::new` takes a couple of minutes on first run (it builds
8.4M points from scratch). The cached dev file makes subsequent runs fast. The
production download path avoids this cost entirely (the transcript is
pre-computed by the ceremony).

---

## 5. Summary of the trust model

| Party | What they must trust | What they must NOT be trusted with |
|---|---|---|
| **Claimant** | 1-of-N honesty of the PSE ceremony | Not the deployer, not the host, not their own cache |
| **Deployer** | The PSE ceremony (same as claimant) | Cannot forge proofs (no trapdoor); cannot swap the SRS (hash-pinned) |
| **Contract** | Nothing runtime — it only checks the proof | — |

The SRS hash in `cli/src/constants.rs` is the **single trust root**. Everything
else (Merkle root, nullifier scheme, recipient binding) is proven in zero
knowledge against it.
