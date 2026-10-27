# Rust Port of BLS Witness Encryption: Implementation Plan

Date: 2026-10-17
Status: Superseded by `2026-10-20-rust-port-server-execution.md` (execution-ready version); kept as design background
Base commit: `dc9ce01` (main)

## Goal

Replace the C++ `witenc` library (about 225 lines in `src/witenc.cpp`) and its pybind11 bindings with a Rust crate and a PyO3 Python module. The Rust version must produce and accept ciphertexts that are byte-compatible with the current C++ implementation (format "v1"). Security bugs that do not change the format get fixed along the way. Format-changing improvements are deferred to a separate, decision-gated phase.

## Ground rules

1. **All work happens in git worktrees.** Nothing is edited in the main checkout at `/Users/bgr/src/BLS-Witness-Encryption`.
2. **All changes stay local.**
   - No `git push`, no `gh pr create`, no changes to remotes, tags on remotes, or GitHub state.
   - No `cargo publish`, `maturin publish`, or PyPI uploads.
   - Network access is limited to downloading dependencies (crates.io, GitHub for CMake `FetchContent`, PyPI for dev tools).
3. **Worktrees live in `.worktrees/` inside the repo**, which is ignored through `.git/info/exclude`. That file is local and never committed, so `.gitignore` stays untouched.
4. **Branches are merged into local `main` only with explicit approval.** By default, finished branches are left for review.
5. **Cleanup** uses `git worktree remove`. Any manual deletion uses `trash`, never `rm`.
6. **Commits** are small, each with its tests, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
7. **Execution style**: red/green TDD, property-based tests, and unit tests (the `/rigorous` workflow), one phase at a time with a checkpoint after each.

## Worktree and branch layout

| Worktree | Branch | Based on | Phases |
|---|---|---|---|
| `.worktrees/cpp-fixes` | `fix/cpp-rng-and-parse` | `main` | 0 (baseline), 1 |
| `.worktrees/rust-port` | `rust-port` | `fix/cpp-rng-and-parse` | 2 to 6 |
| `.worktrees/format-v2` | `format-v2` | `rust-port` | 7 (only if approved) |

`rust-port` is based on the C++ fix branch so that the C++ reference implementation used by the compatibility tests has the safe parser. Otherwise the negative tests (malformed input) would trigger the out-of-bounds read in the unfixed C++.

Setup:

```fish
cd /Users/bgr/src/BLS-Witness-Encryption
echo ".worktrees/" >> .git/info/exclude
git worktree add .worktrees/cpp-fixes -b fix/cpp-rng-and-parse main
# later, after Phase 1 is committed:
git worktree add .worktrees/rust-port -b rust-port fix/cpp-rng-and-parse
```

## Background: established facts

1. **Library structure.** `Scheme::Encrypt(pk, tag, msg)` picks a random scalar `r1` and a random GT element `r2`, then produces:
   - `c1 = r1·G1`
   - `c2 = e(pk, r1·H(tag)) · r2`
   - `c3 = msg XOR keystream(SHA-256(r2))`

   `Decrypt(sig, ct)` recovers `r2 = c2 / e(c1, sig)` and unmasks `c3`.
2. **Dependency chain.** The library uses a fork of Chia's `bls-signatures` (`kofi-dalvik/bls-signatures`), which wraps `blst`. The fork's only addition of note is a GT division operator (`blst_fp12_inverse` plus `blst_fp12_mul`).
3. **blst** is C with Perl-generated assembly for x86-64 and ARMv8, plus a portable C fallback. A Rust port still runs on blst underneath. Rust's memory-safety guarantees cover the witness-encryption layer, which is where all the bugs below are.
4. **`chia-bls`** (Rust crate in `Chia-Network/chia_rs`, built on the `blst` crate) has everything needed, without the crate itself needing `unsafe`:
   - `hash_to_g2_with_dst(msg, dst)`.
   - `PublicKey` and `Signature`, each with `generator()`, `scalar_multiply(int_bytes)`, `negate()` and `Neg`, and `from_bytes`/`to_bytes`.
   - `Signature::pair(&PublicKey) -> GTElement`.
   - `GTElement` with `Mul`, and `from_bytes`/`to_bytes` over `[u8; 576]`.
5. **`chia-bls` has no GT division or inverse.** Decryption avoids needing it by using `c2 / e(c1, sig) = c2 · e(−c1, sig)`. Negating a G1 point is cheap.
6. **GT encoding is a raw memory copy of `blst_fp12`** (Montgomery form, 64-bit little-endian limbs) in both the C++ fork and `chia-bls`. The two are therefore compatible on x86-64 and arm64, but the format is not portable to big-endian hosts. Preserve it in v1.
7. **`scalar_multiply` in `chia-bls`** reduces the input bytes mod r (`blst_scalar_from_be_bytes`) and multiplies with 256 bits. The C++ side builds a `blst_scalar` from 32 big-endian bytes without reduction. Deterministic test vectors must therefore use scalars `< r`, so that both sides agree whatever their reduction behavior.

## v1 compatibility contract

The Rust implementation must match these byte for byte:

| Item | Value |
|---|---|
| Hash-to-G2 DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` (BasicSchemeMPL) |
| Ciphertext layout | `c1 (48, compressed G1) ‖ c2 (576, raw blst_fp12) ‖ c3 (n ≥ 1)` |
| `HashGT` | `SHA-256(GT raw bytes)` (32 bytes) |
| Keystream block `j` | `SHA-256(key ‖ u32_be(j))`, 32 bytes per block |
| `c3` length | message length rounded up to a multiple of 32; padding bytes are `0x00 XOR keystream` |
| Decrypt post-processing | strip **all** trailing `0x00` bytes (lossy; see defect D4) |
| Validation on parse | `c1` valid G1 point, `c2` exactly 576 bytes, `c3` non-empty; no GT subgroup check |
| Empty message | not supported (`c3` would be empty and fails validation). Rust must reject it explicitly with an error |
| Hex form | lowercase hex of the serialized bytes |

## Known defects and how each is handled

| ID | Defect | Location | Fix in | Changes format? |
|---|---|---|---|---|
| D1 | All randomness comes from `std::default_random_engine` (31-bit LCG) seeded with one 32-bit value. An observer of `c1` can brute-force the seed and decrypt without a signature. | `src/witenc.cpp:10-12`, `RandomScalar` at `:201` | Phase 1 (C++) and Phase 2 (Rust uses `OsRng`) | No |
| D2 | `uniform_int_distribution<uint8_t>` is undefined behavior per the C++ standard. | `src/witenc.cpp:12` | Phase 1 (removed with D1) | No |
| D3 | Data race: the Python bindings release the GIL while `encrypt` mutates the global generator. | `bindings/python/witencpy.cpp:70+` | Phase 1 (stateless RNG); not expressible in safe Rust | No |
| D4 | `Deserialize` underflows `c3_size` on input shorter than 624 bytes; the bounds check is tautological, so this is an out-of-bounds read. | `src/witenc.cpp:123-131` | Phase 1 (C++); Rust uses checked slicing | No |
| D5 | Decrypt strips trailing `0x00`, so plaintexts ending in zero bytes do not round-trip. | `src/witenc.cpp:181` | Phase 7 only (v2) | **Yes** |
| D6 | No integrity check: a wrong signature yields garbage, and `c3` is malleable. | design | Phase 7 only (v2) | **Yes** |
| D7 | Secrets (`r1`, `r2` hash, keystream) are not zeroized. | `src/witenc.cpp` | Phase 4 (Rust, `zeroize`) | No |
| D8 | The `bls-signatures` fork is fetched from unpinned `origin/main`. | `CMakeLists.txt:28` | Phase 1 (pin to SHA); Rust uses `Cargo.lock` | No |
| D9 | The bindings switch tests `BUILD_BLS_PYTHON_BINDINGS` instead of the `BUILD_WITENC_…` option. | `CMakeLists.txt:43` | Phase 1 (optional) | No |
| D10 | Random scalars from 32 bytes are biased if reduced mod r (r ≈ 2^254.9). | `RandomScalar` | Phase 2 (Rust samples 64 bytes and reduces) | No |

The rule for the port: **v1 behavior is reproduced faithfully, including D5.** Only format-neutral fixes go in before Phase 7.

## Phase 0: Prerequisites and baseline

Neither `cargo` nor `cmake` is installed (checked 2026-10-17). Python 3.14 and `uv` are available.

1. Install toolchains. These are system changes, so **ask before running**:
   - `brew install rustup` then `rustup-init` (stable toolchain plus `rustfmt`, `clippy`).
   - `brew install cmake`.
   - `cargo install cargo-fuzz cargo-deny` (fuzzing needs `rustup toolchain install nightly`).
   - `uv tool install maturin`.
2. Create the `.worktrees/` exclusion and the `cpp-fixes` worktree.
3. **Baseline the C++ before changing anything.** In `.worktrees/cpp-fixes`:
   - `cmake -S . -B build -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0`
   - `cmake --build build -j`
   - `./build/src/wetest` and `./build/src/webench`
   - Record the `bls-signatures` and `blst` commit SHAs that `FetchContent` resolved.
4. If the C++ does not build on the current Apple clang and arm64 setup, fix the build in its own commit on the `cpp-fixes` branch, and note the time spent. This is the largest schedule risk.

**Exit:** C++ builds, `wetest` passes, and the dependency SHAs are recorded in this plan.

## Phase 1: C++ security fixes (worktree `cpp-fixes`)

These fixes are format-neutral and can be merged on their own.

1. **D4 parser fix (TDD).**
   - Red: add `test_deserialize_rejects_short_input` to `src/test.cpp` (inputs of 0, 47, 623 and 624 bytes must throw `std::invalid_argument`). Build with `-fsanitize=address` so the out-of-bounds read fails visibly.
   - Green: check `bytes.size() < c1_size + c2_size + 1` before the subtraction.
2. **D1, D2 and D3 RNG fix.**
   - Replace the global engine and distribution with `getentropy()` (macOS 10.12+, glibc 2.25+), throwing on failure. This removes all global mutable state, which also removes the data race.
   - A meaningful red test for "is cryptographically random" isn't possible. Verify by code review plus a smoke test that 1,000 scalars are pairwise distinct. State this limit in the commit message.
3. **D8:** pin `BLS_GIT_TAG` to the SHA recorded in Phase 0.
4. **D9 (optional):** correct the bindings option name.

**Exit:** `wetest` passes under ASan, every fix is in its own commit, and nothing is pushed.

## Phase 2: Rust core crate (worktree `rust-port`)

Layout. A Cargo workspace is added at the repo root; the C++ in `src/` is left untouched as the reference.

```
Cargo.toml                 # [workspace] members = ["crates/*"]
crates/witenc/
  src/lib.rs               # #![forbid(unsafe_code)], re-exports
  src/ciphertext.rs        # CipherText { c1: PublicKey, c2: GTElement, c3: Vec<u8> }
  src/keystream.rs         # SHA-256 counter keystream (C++ "OTP")
  src/scheme.rs            # encrypt, encrypt_with_rng, decrypt
  src/error.rs             # Error enum (thiserror)
  tests/                   # integration and compat tests
crates/witenc-py/          # Phase 5
compat/                    # Phase 3 C++ vector tool and fixtures
```

API sketch:

```rust
pub fn encrypt(pk: &PublicKey, tag: &[u8], msg: &[u8]) -> Result<CipherText, Error>;   // OsRng
pub fn encrypt_with_rng<R: RngCore + CryptoRng>(rng: &mut R, pk: &PublicKey, tag: &[u8], msg: &[u8]) -> Result<CipherText, Error>;
pub fn decrypt(sig: &Signature, ct: &CipherText) -> Vec<u8>;
impl CipherText {
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error>;   // parse, don't validate
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_hex(s: &str) -> Result<Self, Error>;
    pub fn to_hex(&self) -> String;
}
```

Notes:
- Dependencies: `chia-bls`, `sha2`, `rand_core` (with `getrandom`), `hex`, `thiserror`. Dev dependencies: `proptest`, `rand_chacha`.
- Decryption uses `c2 · e(−c1, sig)` (fact 5). No direct `blst` dependency is needed.
- Random scalars: 64 bytes from the RNG, passed to `scalar_multiply`, which reduces mod r (D10).
- A random GT element is `e(s1·G1, s2·G2)`, the same construction as the C++.
- A `test-vectors` cargo feature exposes `encrypt_with_scalars(r1, s1, s2, …)` for deterministic known-answer tests. It is off by default.

TDD order, each red then green:
1. Keystream: round trip, block boundaries (31, 32 and 33 bytes), counter encoding.
2. `CipherText` parsing: length errors, invalid `c1`, empty `c3`, round trip through bytes and hex.
3. `encrypt`/`decrypt` round trip with keys from `chia_bls::SecretKey::from_seed` and `chia_bls::sign`; error on empty message.
4. Algebra checks mirroring `src/test.cpp`: bilinearity, and `e(−a, b) · e(a, b) = 1`.

**Exit:** `cargo test`, `cargo clippy -- -D warnings` and `cargo fmt --check` all pass.

## Phase 3: Cross-implementation compatibility harness

1. **C++ vector tool** `compat/witenc_vectors.cpp`, built as CMake target `wevectors` behind `BUILD_WITENC_COMPAT`. It uses only the library's public API, with no changes to `witenc.cpp`, and has these modes:
   - `kat`: deterministic ciphertexts from given `r1, s1, s2` (all `< r`), built from `BuildC2`-equivalent steps, `HashGT` and `MaskMessage`.
   - `encrypt`: random ciphertexts plus the signature, for Rust to decrypt.
   - `decrypt`: reads JSON on stdin and decrypts ciphertexts produced by Rust.
   - `keystream` and `gt`: raw `OTP::Encrypt` outputs and GT bytes for `e(G1, G2)`.
2. **Fixtures** are checked in at `compat/vectors/*.json` (hex fields), generated once from the Phase 1 C++ build. The generation command is recorded in `compat/README.md`.
3. **Rust tests** in `crates/witenc/tests/compat.rs` cover:
   - Known answers: Rust `encrypt_with_scalars` must equal the C++ bytes exactly.
   - C++ to Rust: Rust decrypts every C++ ciphertext correctly.
   - Rust to C++: an `#[ignore]` live test runs the binary named in `WITENC_CPP_BIN`. Run it with `cargo test -- --ignored`.
   - Negative cases: both sides reject the same malformed inputs.
4. **Message corpus:** 1 byte, 31, 32, 33, 1 KiB, random binary, and messages ending in `0x00`. The last group documents D5: both sides must truncate identically.

**Exit:** every compat test passes, including the live round trip in both directions.

## Phase 4: Hardening

1. **Property tests (`proptest`):**
   - Any non-empty message without trailing zeros round-trips.
   - `from_bytes(to_bytes(ct)) == ct`.
   - Decrypting with a wrong signature never returns the plaintext.
   - `from_bytes` never panics on arbitrary input.
2. **`cargo-fuzz` target** on `CipherText::from_bytes` and `from_hex`. Run for at least 10 minutes locally; any crash gets a regression test.
3. **D7:** zeroize the scalar bytes, the `r2` hash and the keystream buffers.
4. **Supply chain:** `cargo-deny` configuration for licenses and advisories; commit `Cargo.lock`.

**Exit:** property tests, the fuzz run and `cargo deny check` are clean.

## Phase 5: Python bindings

1. Add `crates/witenc-py` using PyO3 with maturin, keeping the module name `witencpy` so it is a drop-in replacement.
2. Match the current API:
   - `Scheme.encrypt(pk_bytes, tag, msg)` and `Scheme.decrypt(sig_bytes, ct)`.
   - `CipherText` with `c1`, `c2`, `c3`, `to_hex`, `from_hex`, `validate`, `__eq__`, `__bytes__` and `from_bytes`.
   - `OTP.encrypt` and `OTP.decrypt`.
3. Behavior differences, to be documented:
   - Methods return `bytes` instead of `list[int]`. Existing `bytes(...)` calls still work.
   - `from_bytes` becomes a proper `staticmethod`.
   - Errors raise `ValueError`.
4. Release the GIL around the pairing work. This is safe because the Rust core has no shared mutable state.
5. Build with `abi3` (one wheel per platform) using `maturin develop` in a `uv` virtual environment. Wheels are built locally only.
6. Add a pytest suite, and port `bindings/python/benchmark.py` so it runs unchanged against the new module.
   - Test keys and signatures come from the `chia_rs` Python package.
   - If no `chia_rs` wheel exists for Python 3.14, use `uv` to pin Python 3.12 for the test environment.

**Exit:** pytest passes, and `benchmark.py` runs and passes its correctness checks.

## Phase 6: Performance parity

1. Add `criterion` benchmarks for encrypt, decrypt, serialize and deserialize, matching what `src/bench.cpp` measures.
2. Compare against `webench` on the same machine. Expect parity, because pairings in blst dominate both.
3. Investigate any regression greater than 10% before closing the phase.

**Exit:** a benchmark comparison table is added to this plan.

## Phase 7: Format v2 (decision-gated, worktree `format-v2`)

Do not start without an explicit decision. Proposed content:
- A version byte prefix.
- HKDF-SHA256 over `r2`'s bytes plus a context string, followed by an AEAD cipher (ChaCha20-Poly1305) on the message. This fixes D5 (no padding or stripping) and D6 (wrong signature or tampering becomes an error).
- An optional GT subgroup check on `c2`.
- A portable GT encoding (`blst_bendian_from_fp12`), which would need either `unsafe` or an upstream addition to `chia-bls`.
- v1 decryption stays supported for existing ciphertexts.

## Phase 8: Review and local integration

1. Code review of each branch, using the `superpowers:code-reviewer` agent plus human review of the cryptography.
2. Merge into local `main` on approval: `fix/cpp-rng-and-parse` first, then `rust-port`. **No push.**
3. Update the README build, test and Python instructions in the `rust-port` branch.
4. Remove worktrees with `git worktree remove` once their branches are merged or abandoned.
5. Deciding whether to delete the C++ sources is out of scope. They stay as the reference until that decision is made.

## Estimate

| Phase | Experienced Rust developer |
|---|---|
| 0 Baseline C++ build | 0.5–1 day (the biggest unknown) |
| 1 C++ fixes | 0.5 day |
| 2 Rust core | 0.5–1 day |
| 3 Compat harness | 1–2 days |
| 4 Hardening | 0.5 day |
| 5 Python bindings | 0.5–1 day |
| 6 Benchmarks | 0.25 day |
| **Total (v1)** | **about 3–5 days**; 1–2 weeks for someone newer to Rust |
| 7 Format v2 | +1 day after the design decision |

Done by Claude in worktrees, the coding fits in one or two sessions. The pace is set by the Phase 0 C++ build and by human review of the cryptography.

## Risks and open questions

1. **C++ bitrot.** The fork, blst and libsodium fetches may not build on current Apple clang for arm64. Mitigation: Phase 0 runs first and is time-boxed. If it fails badly, stop and decide whether to fix the build or generate fixtures on a Linux container.
2. **Internal representation of `blst_fp12`.** Both sides must use blst versions with the same internal layout, or the raw GT bytes will differ. The Phase 3 GT vector catches this immediately.
3. **`chia-bls` API stability.** It is versioned for the Chia blockchain, not for third-party use. Pin an exact version.
4. **Old Python bindings won't build on 3.14** (pybind11 era, README says 3.8). They are not needed: compatibility is proven at the Rust level, and the new module is checked against the documented API.
5. **Windows.** `getentropy` is POSIX-only. Is Windows a supported target? If so, the C++ fix needs a `BCryptGenRandom` branch. The Rust side is unaffected.
6. **Who uses v1 today?** The answer determines whether the Phase 1 fixes need to be released urgently, and how long v1 decryption must be supported after v2.

## Out of scope

- Publishing anything (crates.io, PyPI, GitHub).
- Removing the C++ implementation.
- WebAssembly or other language bindings.
- Changing the cryptographic construction beyond Phase 7's proposal.
