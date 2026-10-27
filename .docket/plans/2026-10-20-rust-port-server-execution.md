# Rust Port of BLS Witness Encryption: Server Execution Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. If that skill is not installed, follow the tasks in order and honor every checkpoint and STOP condition below.

**Goal:** Port the C++ `witenc` library and its Python bindings to Rust, byte-compatible with the existing ciphertext format (v1), after first fixing the format-neutral security bugs in the C++.

**Architecture:** A Cargo workspace is added next to the existing C++ (which stays as the reference implementation). The core crate `witenc` uses `chia-bls` (Chia's Rust BLS crate over `blst`) and contains no `unsafe`. A small C++ tool generates test vectors so every Rust behavior is checked against the C++ output. Python bindings use PyO3 and maturin with the same module name, `witencpy`.

**Tech stack:** Rust stable (chia-bls 0.52, sha2 0.10, rand_core 0.6, thiserror 2, zeroize 1, proptest, criterion 0.5, cargo-fuzz, cargo-deny), PyO3 0.29 with maturin, C++17 with CMake 3.14+, Python 3.9+ with uv and pytest.

**Supersedes:** `.docket/plans/2026-10-17-rust-port-witness-encryption.md` (the design-level plan). This document is self-contained; the earlier one is background only.

---

## How to use this document

### For the person moving it to the server

1. Copy the whole repository, including `.git` and the untracked `.docket/` folder. Do **not** use `git push`; this work stays off GitHub.
   ```bash
   rsync -a --exclude 'build/' /Users/bgr/src/BLS-Witness-Encryption/ SERVER:src/BLS-Witness-Encryption/
   ```
2. On the server, start Claude Code in the repository root and say: "Execute `.docket/plans/2026-10-20-rust-port-server-execution.md`."
3. Edit the **Decisions** section below first if any default is wrong.

### For the executing session

- **`$REPO` means the absolute path of the repository root on this machine.** Claude Code shells do not keep variables between calls, so substitute the real path in every command.
- **This plan file is untracked**, so it does not exist inside the worktrees. Always read it from `$REPO/.docket/plans/`.
- **The server will not have the author's personal Claude settings.** The ground rules below restate the ones that matter.

## Decisions (defaults; edit before starting if needed)

| # | Decision | Default |
|---|---|---|
| 1 | Install toolchains on this server (rustup, cmake, uv, cargo tools) | **Yes**, user-level installs preferred. `sudo` only if it works non-interactively |
| 2 | Support Windows in the C++ RNG fix | **No.** POSIX `getentropy` only |
| 3 | Do the format v2 work (AEAD, length prefix, version byte) | **No.** Out of scope for this run |
| 4 | Merge finished branches into `main` | **No.** Leave branches for human review |

## Ground rules

1. **Worktrees only.** Never edit files in the main checkout at `$REPO`, except to write the results file in `$REPO/.docket/wrap-ups/`.
2. **Everything stays on this machine.**
   - Never run `git push`, `gh pr create`, `git remote add/set-url`, `cargo publish`, `maturin publish` or `twine upload`.
   - Every crate sets `publish = false`.
   - Downloading dependencies (crates.io, PyPI, GitHub via CMake `FetchContent`, rustup) is fine.
3. **Never use `rm`.** Use `trash` (macOS built-in, or `trash-cli` on Linux, installed in Task 0.2). Remove worktrees only with `git worktree remove`.
4. **Never use the bullet character (Unicode U+2022)** in any document or output you write. Use `-` for lists.
5. **Commits.** Make small commits, each with its tests. Use conventional subjects (`fix:`, `feat:`, `test:`, `build:`, `docs:`, `chore:`). End every message with a blank line and:
   ```
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   ```
   Use a heredoc:
   ```bash
   git -C <worktree> commit -m "$(cat <<'EOF'
   fix: subject here

   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   EOF
   )"
   ```
6. **Test fixtures are generated, never hand-edited.** Files in `compat/vectors/` come only from the C++ tool. If a Rust test disagrees with a fixture, the Rust code is wrong until proven otherwise.
7. **The C++ is the reference in the `rust-port` branch.** Do not change C++ behavior there to make Rust tests pass.

### Checkpoints

At the end of every phase:
1. Run the phase's **Exit check**.
2. Append a dated status line to the results file (`$REPO/.docket/wrap-ups/2026-10-20-rust-port-results.md`, created in Task 0.1).
3. Continue to the next phase, unless a STOP condition applies.

### STOP conditions

Stop work, write what happened and what you tried into the results file, and end the session if any of these occur:
1. The baseline C++ build (Task 0.3) still fails after three distinct fix attempts or about two hours of effort.
2. The baseline `wetest` fails before any change has been made.
3. A compat test fails and the cause is not a bug in the new Rust code. This includes any disagreement in GT bytes, signatures or ciphertext bytes that persists after checking the Rust code against this plan.
4. A crash found by fuzzing is inside `chia-bls` or `blst` rather than in `witenc`.
5. Any step would require pushing, publishing, interactive `sudo`, or deleting files outside `$REPO`.

## Background (read once)

**The scheme.**
- `Encrypt(pk, tag, msg)` picks a random scalar `r1` and a random G_T element `r2 = e(s1·G1, s2·G2)`, then outputs:
  - `c1 = r1·G1`
  - `c2 = e(pk, r1·H(tag)) · r2`
  - `c3 = msg XOR keystream(SHA-256(r2))`
- `H` is hash-to-G2 with the BasicSchemeMPL domain tag.
- `Decrypt(sig, ct)` computes `r2 = c2 / e(c1, sig)` and unmasks `c3`. It works because `sig = sk·H(tag)` and `pk = sk·G1`.

**Defects being fixed** (line numbers refer to `main` at `dc9ce01`):

| ID | Defect | Where | Handled in |
|---|---|---|---|
| D1 | All randomness comes from `std::default_random_engine` (31-bit LCG) seeded with one 32-bit value. Anyone who sees `c1` can brute-force the seed and decrypt without a signature. | `src/witenc.cpp:10-12`, `:201` | Task 1.2; Rust uses `OsRng` |
| D2 | `uniform_int_distribution<uint8_t>` is undefined behavior in C++. | `src/witenc.cpp:12` | Task 1.2 |
| D3 | Data race: the Python bindings release the GIL while `encrypt` mutates the global generator. | `bindings/python/witencpy.cpp:70` | Task 1.2 (stateless RNG); Rust core has no shared state |
| D4 | `Deserialize` underflows `c3_size` for inputs shorter than 624 bytes, making the bounds check useless. Result: out-of-bounds read. | `src/witenc.cpp:123-131` | Task 1.1; Rust uses checked slicing |
| D11 | `OTP::Exec` reads past the 32-byte hash when the key is longer than 32 bytes. | `src/witenc.cpp:142-173` | Task 1.3 |
| D12 | `OTP::Exec` divides by zero when the key is empty. | same | Task 1.3 |
| D8 | The `bls-signatures` fork is fetched from unpinned `origin/main`. | `CMakeLists.txt:28` | Task 1.4; Rust uses `Cargo.lock` |
| D7 | Secret intermediate values are never wiped from memory. | `src/witenc.cpp` | Rust uses `zeroize` (Task 2.4) |
| D10 | 32 random bytes reduced mod r give biased scalars. | `RandomScalar` | Rust samples 64 bytes (Task 2.4) |
| D5 | Decrypt strips *all* trailing `0x00` bytes, so such plaintexts don't round-trip. | `src/witenc.cpp:181` | **Kept** (it is part of v1) |
| D6 | No integrity check: a wrong signature yields garbage, not an error. | design | **Kept** (it is part of v1) |

D5 and D6 change the ciphertext format if fixed, so they are reproduced faithfully. Defect IDs match the earlier plan; D11 and D12 are new.

**v1 compatibility contract.** The Rust code must match all of these exactly:

| Item | Value |
|---|---|
| Hash-to-G2 domain tag | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` |
| Ciphertext bytes | `c1` (48, compressed G1) then `c2` (576, raw `blst_fp12` memory) then `c3` (at least 1 byte) |
| `c2` encoding | raw memory copy of `blst_fp12`, used identically by the C++ fork and by `chia-bls`'s `GTElement::to_bytes` |
| Keystream key | `SHA-256(c2-style raw bytes of r2)` |
| Keystream block `j` | `SHA-256(key ‖ u32_be(j))`, truncated to `key.len()` bytes |
| `c3` length | message length rounded up to a whole number of blocks |
| Decrypt | strips every trailing `0x00` byte |
| Parsing | requires `c1` to be a valid G1 point (the point at infinity counts as valid); `c2` is not checked |

**Facts about `chia-bls` 0.52 that the code relies on** (verified from its source on 2026-10-17):
- **Re-exports:** `PublicKey` (G1), `Signature` (G2), `SecretKey`, `GTElement` and `hash_to_g2_with_dst`.
- **Point operations:** `PublicKey` and `Signature` each have `generator()`, `scalar_multiply(&[u8])` (big-endian bytes of any length, reduced mod r) and `from_bytes`/`to_bytes`. `PublicKey` also implements `Neg` for both `PublicKey` and `&PublicKey`.
- **Pairing:** `Signature::pair(&self, &PublicKey) -> GTElement`.
- **`GTElement`:** `from_bytes(&[u8; 576])`, `to_bytes() -> [u8; 576]`, and `&a * &b`. There is **no division or inverse**, so decryption computes `c2 · e(−c1, sig)` instead of `c2 / e(c1, sig)`.
- **Keys:** `SecretKey::from_seed(&[u8])`, `public_key()` and `to_bytes() -> [u8; 32]`. `chia_bls::sign` uses the *augmented* scheme, so this crate provides `sign_tag` for BasicSchemeMPL signatures.
- **Build:** it builds `blst` with the `portable` feature. Despite the build log saying "without ISA extensions", portable blst (0.3.16) assembles both the ADX/MULX and plain field-arithmetic paths and picks one at run time via CPUID (`__blst_platform_cap`), so expect roughly the same speed as an ADX build.

## Worktree and branch layout

| Worktree | Branch | Based on | Phases |
|---|---|---|---|
| `$REPO/.worktrees/cpp-fixes` | `fix/cpp-rng-and-parse` | `main` | 0, 1 |
| `$REPO/.worktrees/rust-port` | `rust-port` | `fix/cpp-rng-and-parse` | 2 to 7 |

`rust-port` builds on the fixed C++ so that the reference implementation can safely parse the malformed inputs used in the compat tests.

---

## Phase 0: Environment and baseline

### Task 0.1: Check the repository and set up local ignores

**Step 1: Confirm the starting state**

Run: `git -C $REPO status --short && git -C $REPO log --oneline -1 && git -C $REPO worktree list`

Expected:
- `?? .docket/` (nothing else uncommitted).
- HEAD is `dc9ce01 Updated test command`, or a later commit if the author added one.
- Only the main worktree is listed.

**Step 2: Add local-only ignores** (they live in `.git/info/exclude`, which is never committed)

```bash
printf '.worktrees/\nbuild-asan/\n' >> $REPO/.git/info/exclude
```

**Step 3: Create the results file**

```bash
mkdir -p $REPO/.docket/wrap-ups
printf '# Rust Port Results\n\nPlan: .docket/plans/2026-10-20-rust-port-server-execution.md\n\n## Status log\n\n' > $REPO/.docket/wrap-ups/2026-10-20-rust-port-results.md
```

### Task 0.2: Install toolchains

First check what already exists: `uname -sm; for t in git cc c++ cmake cargo rustup python3 uv maturin trash; do printf '%s: ' $t; command -v $t || echo missing; done`

Install only what is missing.

**Linux (Debian/Ubuntu):**
```bash
sudo -n apt-get update && sudo -n apt-get install -y build-essential git pkg-config python3 python3-venv curl  # skip if sudo -n fails and these already exist
curl -LsSf https://astral.sh/uv/install.sh | sh                       # uv, user-level
uv tool install cmake                                                 # only if apt cmake is missing or older than 3.14
uv tool install trash-cli                                             # provides `trash`
uv tool install maturin
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal -c rustfmt,clippy
```

**macOS:** `brew install cmake rustup uv && rustup-init -y --profile minimal -c rustfmt,clippy && uv tool install maturin`. `trash` is built in.

**Then, on both:**
```bash
source "$HOME/.cargo/env"
rustup toolchain install nightly --profile minimal     # cargo-fuzz needs nightly
cargo install --locked cargo-fuzz cargo-deny
```

Expected: `cargo --version`, `cmake --version` (3.14 or newer), `uv --version`, `maturin --version`, `cargo fuzz --version` and `cargo deny --version` all print versions.

Append the tool versions to the results file.

### Task 0.3: Create the C++ worktree and build the baseline

**Step 1: Create the worktree**

```bash
git -C $REPO worktree add $REPO/.worktrees/cpp-fixes -b fix/cpp-rng-and-parse main
```

**Step 2: Configure and build (Release)**

```bash
cd $REPO/.worktrees/cpp-fixes
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0
cmake --build build -j4
```

Expected: the build finishes with `build/src/wetest` and `build/src/webench` present.

If the build fails:
- Fix it with the smallest possible change, in its own `build:` commit on this branch.
- Typical causes: a new compiler warning treated as an error, a missing `#include`, or the fork's `origin/main` having moved.
- Remember STOP condition 1.

**Step 3: Run the baseline tests and benchmark**

```bash
./build/src/wetest; echo "exit=$?"
./build/src/webench
```

Expected: `exit=0`. Save the `webench` output in the results file under "Baseline C++ benchmark".

**Step 4: Record the dependency commits**

```bash
git -C build/_deps/bls-src rev-parse HEAD
ls build/_deps
```

Record the `bls-src` commit hash in the results file. Task 1.4 needs it.

**Step 5: Build the AddressSanitizer variant** (used by Phase 1 to make memory errors visible)

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
cmake --build build-asan -j4 && ./build-asan/src/wetest; echo "exit=$?"
```

Expected: `exit=0` with no AddressSanitizer report.

**Exit check (Phase 0):** both builds succeed, and `wetest` passes in both.

---

## Phase 1: C++ security fixes (worktree `cpp-fixes`)

All commands run in `$REPO/.worktrees/cpp-fixes`. Rebuild with `cmake --build build-asan -j4 && cmake --build build -j4`.

### Task 1.1: Reject short ciphertexts in `Deserialize` (D4)

**Files:**
- Modify: `src/test.cpp` (add a test and call it from `main`)
- Modify: `src/witenc.cpp:118-135` (`CipherText::Deserialize`)

**Step 1: Write the failing test.** Add this above `int main` in `src/test.cpp`:

```cpp
void test_deserialize_rejects_short_input()
{
    for (size_t n : {0, 1, 47, 48, 623, 624}) {
        vector<uint8_t> input(n, 0);
        bool threw = false;
        try {
            CipherText::Deserialize(input);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ASSERT(threw);
    }
}
```

Add `test_deserialize_rejects_short_input();` as the first call in `main`.

**Step 2: Run it and watch it fail**

Run: `cmake --build build-asan -j4 && ./build-asan/src/wetest; echo "exit=$?"`

Expected: an AddressSanitizer report (`heap-buffer-overflow`, or a SEGV on an address near zero) and a non-zero exit.

**Step 3: Fix it.** In `CipherText::Deserialize`, replace

```cpp
        size_t c3_size = bytes.size() - c1_size - c2_size;

        if (bytes.size() < (c1_size + c2_size + c3_size)) {
            throw std::invalid_argument("Bad Ciphertext: Invalid bytes");
        }
```

with

```cpp
        if (bytes.size() <= c1_size + c2_size) {
            throw std::invalid_argument("Bad Ciphertext: Invalid bytes");
        }

        size_t c3_size = bytes.size() - c1_size - c2_size;
```

**Step 4: Run the tests and watch them pass**

Run: `cmake --build build-asan -j4 && ./build-asan/src/wetest; echo "exit=$?"`

Expected: `exit=0` and no ASan output.

**Step 5: Commit** `src/test.cpp src/witenc.cpp` with the subject `fix: reject ciphertexts too short to hold c3 instead of reading out of bounds`.

### Task 1.2: Use the OS random number generator (D1, D2, D3)

**Files:**
- Modify: `src/witenc.cpp:1-12` (includes and globals)
- Modify: `src/witenc.cpp:201-213` (`Helpers::RandomScalar`)
- Modify: `src/test.cpp`

There is no meaningful failing test for "is cryptographically random". The guard is the source check in Step 4, plus a distinctness smoke test. Say so in the commit message.

**Step 1: Add the smoke test** (it passes before and after the change). Add `#include <set>` at the top of `src/test.cpp`, then:

```cpp
void test_random_scalars_are_distinct()
{
    std::set<vector<uint8_t>> seen;
    for (int i = 0; i < 1000; i++) {
        blst_scalar s = Helpers::RandomScalar();
        seen.insert(vector<uint8_t>(s.b, s.b + 32));
    }
    ASSERT(seen.size() == 1000);
}
```

Call it from `main`.

**Step 2: Replace the generator.** In `src/witenc.cpp`:
- Delete `#include <random>` and the three global lines (`std::random_device device;`, `std::default_random_engine generator(device());`, `std::uniform_int_distribution<uint8_t> byte_distribution(0, 255);`).
- Add these includes after `#include <iostream>`:

```cpp
#include <stdexcept>
#include <unistd.h>
#include <sys/random.h>
```

- In `Helpers::RandomScalar`, replace

```cpp
        for (int i = 0; i < 32; i++) {
            random_bytes[i] = byte_distribution(generator);
        }
```

with

```cpp
        if (getentropy(random_bytes.data(), random_bytes.size()) != 0) {
            throw std::runtime_error("getentropy failed");
        }
```

**Step 3: Build and test both variants**

Run: `cmake --build build-asan -j4 && ./build-asan/src/wetest; echo "exit=$?"; cmake --build build -j4 && ./build/src/wetest; echo "exit=$?"`

Expected: both print `exit=0`.

**Step 4: Source check**

Run: `grep -nE "default_random_engine|uniform_int_distribution|random_device" src/witenc.cpp; echo "matches=$?"`

Expected: no output and `matches=1`.

**Step 5: Commit** `src/witenc.cpp src/test.cpp` with the subject `fix: draw randomness from getentropy instead of a 32-bit-seeded LCG`. In the body, note that this removes the global generator (and with it the data race under the GIL-released Python bindings), that it doesn't change the format, and that there is no failing test because randomness quality can't be unit-tested.

### Task 1.3: Reject OTP keys that are empty or longer than 32 bytes (D11, D12)

**Files:**
- Modify: `src/test.cpp`
- Modify: `src/witenc.cpp` (`OTP::Exec`, first lines)

**Step 1: Write the failing test**

```cpp
void test_otp_rejects_bad_key_lengths()
{
    vector<uint8_t> msg = {1, 2, 3};
    for (size_t n : {0, 33, 64}) {
        vector<uint8_t> key(n, 7);
        bool threw = false;
        try {
            OTP::Encrypt(key, msg);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ASSERT(threw);
    }
}
```

Call it from `main`.

**Step 2: Run it and watch it fail**

Run: `cmake --build build-asan -j4 && ./build-asan/src/wetest; echo "exit=$?"`

Expected: a crash from integer division by zero (`SIGFPE`) for the empty key, or an ASan report.

**Step 3: Fix it.** Make these the first lines of `OTP::Exec`:

```cpp
        if (key.empty() || key.size() > 32) {
            throw std::invalid_argument("OTP key must be 1 to 32 bytes");
        }
```

**Step 4: Run the tests and watch them pass.** Same command as Step 2. Expected: `exit=0`.

**Step 5: Commit** with the subject `fix: reject OTP keys that are empty or longer than the hash`.

### Task 1.4: Pin the `bls-signatures` dependency (D8)

**Files:**
- Modify: `CMakeLists.txt:28`

**Step 1:** Replace `set(BLS_GIT_TAG "origin/main")` with `set(BLS_GIT_TAG "<commit hash recorded in Task 0.3 Step 4>")`.

**Step 2:** Reconfigure from scratch to prove the pin works:

```bash
trash build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 && cmake --build build -j4 && ./build/src/wetest; echo "exit=$?"
```

Expected: `exit=0`.

**Step 3: Commit** with the subject `build: pin bls-signatures fork to a fixed commit`.

**Exit check (Phase 1):**
- `./build-asan/src/wetest` and `./build/src/wetest` both exit 0.
- `git -C $REPO/.worktrees/cpp-fixes log --oneline main..` shows the new commits.
- `git -C $REPO/.worktrees/cpp-fixes status --short` is empty.

---

## Phase 2: Rust core crate (worktree `rust-port`)

### Task 2.1: Create the worktree and the workspace skeleton

**Step 1: Create the worktree**

```bash
git -C $REPO worktree add $REPO/.worktrees/rust-port -b rust-port fix/cpp-rng-and-parse
```

All commands from here on run in `$REPO/.worktrees/rust-port`.

**Files:**
- Create: `Cargo.toml`
- Create: `crates/witenc/Cargo.toml`
- Create: `crates/witenc/src/lib.rs`
- Create: `crates/witenc/src/error.rs`
- Create: `crates/witenc/benches/scheme.rs` and `crates/witenc/tests/compat.rs` (placeholders; Cargo refuses to load a manifest whose declared targets have no file)
- Modify: `.gitignore` (append `/target`)

**Step 2: Write `Cargo.toml`** (workspace root)

```toml
[workspace]
resolver = "2"
members = ["crates/*"]
exclude = ["crates/witenc/fuzz"]

# blst is C and assembly; keep it optimized in debug and test builds too,
# or pairing-heavy tests run about 10x slower.
[profile.dev.package."*"]
opt-level = 3
```

**Step 3: Write `crates/witenc/Cargo.toml`**

```toml
[package]
name = "witenc"
version = "0.1.0"
edition = "2021"
publish = false
description = "Witness encryption based on BLS signatures (Rust port of the C++ witenc)"

[features]
# Exposes deterministic encryption for cross-checking against the C++ code.
test-vectors = []

[dependencies]
chia-bls = "0.52"
hex = "0.4"
rand_core = { version = "0.6", features = ["getrandom"] }
sha2 = "0.10"
thiserror = "2"
zeroize = "1"

[dev-dependencies]
criterion = "0.5"
proptest = "1"
rand_chacha = "0.3"

[[test]]
name = "compat"
required-features = ["test-vectors"]

[[bench]]
name = "scheme"
harness = false
```

**Step 4: Write `crates/witenc/src/error.rs`**

```rust
/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("Bad Ciphertext: Invalid bytes (got {0} bytes, need more than 624)")]
    TooShort(usize),
    #[error("Bad Ciphertext: Invalid c1")]
    InvalidC1,
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("message must not be empty")]
    EmptyMessage,
    #[error("OTP key must be 1 to 32 bytes, got {0}")]
    InvalidKeyLength(usize),
}
```

**Step 5: Write `crates/witenc/src/lib.rs`**

```rust
//! Witness encryption based on BLS signatures; a Rust port of the C++ `witenc`.
//!
//! A message encrypted to `(pk, tag)` can be decrypted by anyone holding a
//! BasicSchemeMPL signature by `pk` on `tag`. Ciphertexts are byte-compatible
//! with the C++ implementation (format v1).
#![forbid(unsafe_code)]

mod error;

pub use chia_bls;
pub use error::Error;
```

**Step 6: Create the placeholders and ignore build output**
- `crates/witenc/benches/scheme.rs` containing `fn main() {}` (Task 6.1 fills it in).
- `crates/witenc/tests/compat.rs` containing the single line `// Filled in by Task 3.2.`
- Append `/target` to `.gitignore`.

**Step 7: Build**

Run: `cargo build -p witenc`

Expected: `Finished` with no errors. The first build downloads crates and compiles blst.

**Step 8: Commit** `Cargo.toml Cargo.lock crates/witenc .gitignore` with the subject `build: add Rust workspace and witenc crate skeleton`.

### Task 2.2: Keystream (`otp` module)

**Files:**
- Create: `crates/witenc/tests/otp.rs`
- Create: `crates/witenc/src/otp.rs`
- Modify: `crates/witenc/src/lib.rs` (add `pub mod otp;`)

**Step 1: Write the failing tests** in `crates/witenc/tests/otp.rs`

```rust
use sha2::{Digest, Sha256};
use witenc::{otp, Error};

#[test]
fn round_trips() {
    let key = [7u8; 32];
    let ct = otp::encrypt(&key, b"Hello World!").unwrap();
    assert_eq!(ct.len(), 32);
    assert_eq!(otp::decrypt(&key, &ct).unwrap(), b"Hello World!");
}

#[test]
fn pads_to_whole_blocks() {
    let key = [1u8; 32];
    for (len, expected) in [(0, 0), (1, 32), (31, 32), (32, 32), (33, 64)] {
        assert_eq!(otp::encrypt(&key, &vec![9; len]).unwrap().len(), expected, "len {len}");
    }
}

#[test]
fn block_size_follows_key_length() {
    assert_eq!(otp::encrypt(&[1u8; 16], &[9; 17]).unwrap().len(), 32);
}

#[test]
fn blocks_are_sha256_of_key_and_big_endian_counter() {
    let key = [3u8; 32];
    let ct = otp::encrypt(&key, &[0u8; 64]).unwrap();
    let block = |j: u32| Sha256::new().chain_update(key).chain_update(j.to_be_bytes()).finalize().to_vec();
    assert_eq!(ct[..32], block(0)[..]);
    assert_eq!(ct[32..], block(1)[..]);
}

#[test]
fn rejects_bad_key_lengths() {
    assert_eq!(otp::encrypt(&[], b"x"), Err(Error::InvalidKeyLength(0)));
    assert_eq!(otp::encrypt(&[0; 33], b"x"), Err(Error::InvalidKeyLength(33)));
}

#[test]
fn decrypt_strips_trailing_zeros_as_in_v1() {
    let key = [5u8; 32];
    let ct = otp::encrypt(&key, &[1, 2, 0, 0]).unwrap();
    assert_eq!(otp::decrypt(&key, &ct).unwrap(), vec![1, 2]);
}
```

**Step 2: Run them and watch them fail**

Run: `cargo test -p witenc --test otp`

Expected: compile error ``unresolved import `witenc::otp` ``.

**Step 3: Implement `crates/witenc/src/otp.rs`**

```rust
//! Hash-based keystream (the C++ `OTP` class): block `j` is
//! `SHA-256(key || be32(j))`, truncated to the key length.

use sha2::{Digest, Sha256};

use crate::Error;

const MAX_KEY_LEN: usize = 32;

/// XORs `msg` with the keystream. The output is padded up to a whole number
/// of `key.len()`-byte blocks, as in the C++ `OTP::Exec`.
pub fn encrypt(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidKeyLength(key.len()));
    }
    let block_len = key.len();
    let blocks = msg.len().div_ceil(block_len);
    let mut out = Vec::with_capacity(blocks * block_len);
    for j in 0..blocks {
        let pad = Sha256::new()
            .chain_update(key)
            .chain_update((j as u32).to_be_bytes())
            .finalize();
        out.extend((0..block_len).map(|i| msg.get(j * block_len + i).copied().unwrap_or(0) ^ pad[i]));
    }
    Ok(out)
}

/// Inverse of [`encrypt`]. Strips every trailing zero byte, so plaintexts
/// ending in `0x00` do not round-trip (v1 behavior).
pub fn decrypt(key: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
    let mut msg = encrypt(key, ct)?;
    let len = msg.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    msg.truncate(len);
    Ok(msg)
}
```

Add `pub mod otp;` to `lib.rs` after `mod error;`.

**Step 4: Run them and watch them pass**

Run: `cargo test -p witenc --test otp`

Expected: `test result: ok. 6 passed`.

**Step 5: Commit** with the subject `feat: add SHA-256 counter keystream matching C++ OTP`.

### Task 2.3: `CipherText` parsing and serialization

**Files:**
- Create: `crates/witenc/tests/ciphertext.rs`
- Create: `crates/witenc/src/ciphertext.rs`
- Modify: `crates/witenc/src/lib.rs`

**Step 1: Write the failing tests** in `crates/witenc/tests/ciphertext.rs`

```rust
use witenc::chia_bls::PublicKey;
use witenc::{CipherText, Error, C1_LEN, C2_LEN};

fn valid_bytes(c3_len: usize) -> Vec<u8> {
    let mut b = PublicKey::generator().to_bytes().to_vec();
    b.extend([0xab; C2_LEN]);
    b.extend(vec![0xcd; c3_len]);
    b
}

#[test]
fn parses_and_reserializes() {
    let bytes = valid_bytes(32);
    let ct = CipherText::from_bytes(&bytes).unwrap();
    assert_eq!(ct.c1(), &PublicKey::generator());
    assert_eq!(ct.c2(), &[0xab; C2_LEN]);
    assert_eq!(ct.c3(), &[0xcd; 32][..]);
    assert_eq!(ct.to_bytes(), bytes);
}

#[test]
fn rejects_inputs_without_c3() {
    for n in [0, 1, C1_LEN - 1, C1_LEN, C1_LEN + C2_LEN - 1, C1_LEN + C2_LEN] {
        assert_eq!(CipherText::from_bytes(&vec![0; n]), Err(Error::TooShort(n)));
    }
}

#[test]
fn rejects_invalid_c1() {
    let mut bytes = valid_bytes(1);
    bytes[0] &= 0x7f; // clear the compression flag
    assert_eq!(CipherText::from_bytes(&bytes), Err(Error::InvalidC1));
}

#[test]
fn hex_round_trips() {
    let ct = CipherText::from_bytes(&valid_bytes(5)).unwrap();
    assert_eq!(CipherText::from_hex(&ct.to_hex()).unwrap(), ct);
    assert!(matches!(CipherText::from_hex("zz"), Err(Error::InvalidHex(_))));
}

#[test]
fn equality_covers_c3() {
    let a = valid_bytes(3);
    let mut b = a.clone();
    *b.last_mut().unwrap() ^= 1;
    assert_ne!(CipherText::from_bytes(&a).unwrap(), CipherText::from_bytes(&b).unwrap());
}
```

**Step 2: Run them and watch them fail**

Run: `cargo test -p witenc --test ciphertext`

Expected: compile error ``unresolved imports `witenc::CipherText` ``.

**Step 3: Implement `crates/witenc/src/ciphertext.rs`**

```rust
use chia_bls::PublicKey;

use crate::Error;

/// Length of `c1`, a compressed G1 point.
pub const C1_LEN: usize = 48;
/// Length of `c2`, the raw `blst_fp12` encoding used by both Chia's C++ and Rust code.
pub const C2_LEN: usize = 576;

/// A v1 ciphertext, serialized as `c1 || c2 || c3`. Values are only created
/// by parsing or encryption, so every instance satisfies the C++ `Validate()` rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherText {
    c1: PublicKey,
    c2: [u8; C2_LEN],
    c3: Vec<u8>,
}

impl CipherText {
    pub(crate) fn new(c1: PublicKey, c2: [u8; C2_LEN], c3: Vec<u8>) -> Self {
        debug_assert!(!c3.is_empty());
        Self { c1, c2, c3 }
    }

    pub fn c1(&self) -> &PublicKey {
        &self.c1
    }

    pub fn c2(&self) -> &[u8; C2_LEN] {
        &self.c2
    }

    pub fn c3(&self) -> &[u8] {
        &self.c3
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() <= C1_LEN + C2_LEN {
            return Err(Error::TooShort(bytes.len()));
        }
        let (c1, rest) = bytes.split_at(C1_LEN);
        let (c2, c3) = rest.split_at(C2_LEN);
        let c1 = PublicKey::from_bytes(c1.try_into().expect("split at C1_LEN"))
            .map_err(|_| Error::InvalidC1)?;
        Ok(Self::new(c1, c2.try_into().expect("split at C2_LEN"), c3.to_vec()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.c1.to_bytes()[..], &self.c2[..], &self.c3[..]].concat()
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidHex(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}
```

Add `mod ciphertext;` and `pub use ciphertext::{CipherText, C1_LEN, C2_LEN};` to `lib.rs`.

**Step 4: Run them and watch them pass**

Run: `cargo test -p witenc --test ciphertext`

Expected: `test result: ok. 5 passed`.

**Step 5: Commit** with the subject `feat: add CipherText parsing and serialization`.

### Task 2.4: Encrypt, decrypt and `sign_tag`

**Files:**
- Create: `crates/witenc/tests/scheme.rs`
- Create: `crates/witenc/src/scheme.rs`
- Modify: `crates/witenc/src/lib.rs`

**Step 1: Write the failing tests** in `crates/witenc/tests/scheme.rs`

```rust
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use witenc::chia_bls::{PublicKey, SecretKey, Signature};
use witenc::{decrypt, encrypt, encrypt_with_rng, sign_tag, CipherText, Error};

fn keys(seed: u8) -> (SecretKey, PublicKey) {
    let sk = SecretKey::from_seed(&[seed; 32]);
    let pk = sk.public_key();
    (sk, pk)
}

#[test]
fn signature_on_tag_decrypts() {
    let (sk, pk) = keys(1);
    let ct = encrypt(&pk, b"world", b"hello").unwrap();
    assert_eq!(decrypt(&sign_tag(&sk, b"world"), &ct), b"hello");
}

#[test]
fn signature_on_other_tag_does_not_decrypt() {
    let (sk, pk) = keys(1);
    let ct = encrypt(&pk, b"world", b"hello").unwrap();
    assert_ne!(decrypt(&sign_tag(&sk, b"other"), &ct), b"hello");
}

#[test]
fn other_key_does_not_decrypt() {
    let (_, pk) = keys(1);
    let (other, _) = keys(2);
    let ct = encrypt(&pk, b"world", b"hello").unwrap();
    assert_ne!(decrypt(&sign_tag(&other, b"world"), &ct), b"hello");
}

#[test]
fn rejects_empty_message() {
    let (_, pk) = keys(1);
    assert_eq!(encrypt(&pk, b"t", b""), Err(Error::EmptyMessage));
}

#[test]
fn same_rng_seed_gives_same_ciphertext() {
    let (_, pk) = keys(1);
    let a = encrypt_with_rng(&mut ChaCha20Rng::from_seed([9; 32]), &pk, b"t", b"m").unwrap();
    let b = encrypt_with_rng(&mut ChaCha20Rng::from_seed([9; 32]), &pk, b"t", b"m").unwrap();
    assert_eq!(a, b);
}

#[test]
fn encryption_is_randomized() {
    let (_, pk) = keys(1);
    assert_ne!(encrypt(&pk, b"t", b"m").unwrap(), encrypt(&pk, b"t", b"m").unwrap());
}

#[test]
fn decrypts_after_serialization() {
    let (sk, pk) = keys(3);
    let ct = encrypt(&pk, b"tag", b"payload").unwrap();
    let parsed = CipherText::from_bytes(&ct.to_bytes()).unwrap();
    assert_eq!(decrypt(&sign_tag(&sk, b"tag"), &parsed), b"payload");
}

#[test]
fn trailing_zeros_are_stripped_as_in_v1() {
    let (sk, pk) = keys(4);
    let ct = encrypt(&pk, b"tag", &[1, 2, 0]).unwrap();
    assert_eq!(decrypt(&sign_tag(&sk, b"tag"), &ct), vec![1, 2]);
}

#[test]
fn negating_a_pairing_input_inverts_the_result() {
    // The identity decrypt relies on: e(-P, Q) * e(P, Q) * x == x.
    let p = PublicKey::generator();
    let q = Signature::generator();
    let x = q.pair(&p);
    let product = &(&q.pair(&-&p) * &q.pair(&p)) * &x;
    assert_eq!(product, x);
}
```

**Step 2: Run them and watch them fail**

Run: `cargo test -p witenc --test scheme`

Expected: compile error ``unresolved imports `witenc::decrypt` `` (and the other functions).

**Step 3: Implement `crates/witenc/src/scheme.rs`**

```rust
use chia_bls::{hash_to_g2_with_dst, GTElement, PublicKey, SecretKey, Signature};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{otp, CipherText, Error};

/// Hash-to-G2 domain separation tag of BasicSchemeMPL in Chia's bls-signatures.
pub const BASIC_SCHEME_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Random bytes per scalar; reducing 64 bytes mod r leaves negligible bias.
const SCALAR_SEED_LEN: usize = 64;

/// Encrypts `msg` so that a BasicSchemeMPL signature by `pk` on `tag` decrypts it.
pub fn encrypt(pk: &PublicKey, tag: &[u8], msg: &[u8]) -> Result<CipherText, Error> {
    encrypt_with_rng(&mut OsRng, pk, tag, msg)
}

/// [`encrypt`] with caller-supplied randomness.
pub fn encrypt_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    tag: &[u8],
    msg: &[u8],
) -> Result<CipherText, Error> {
    let r1 = random_scalar(rng);
    let s1 = random_scalar(rng);
    let s2 = random_scalar(rng);
    encrypt_inner(pk, tag, msg, &r1[..], &s1[..], &s2[..])
}

/// Deterministic encryption for cross-checking against the C++ code.
/// Scalars are big-endian and must be below the group order.
#[cfg(feature = "test-vectors")]
pub fn encrypt_with_scalars(
    pk: &PublicKey,
    tag: &[u8],
    msg: &[u8],
    r1: &[u8; 32],
    s1: &[u8; 32],
    s2: &[u8; 32],
) -> Result<CipherText, Error> {
    encrypt_inner(pk, tag, msg, r1, s1, s2)
}

/// Decrypts `ct` with the witness `sig`. A wrong witness yields garbage
/// rather than an error, because v1 has no integrity check.
pub fn decrypt(sig: &Signature, ct: &CipherText) -> Vec<u8> {
    // c2 / e(c1, sig), computed as c2 * e(-c1, sig) because chia-bls has no GT inverse.
    let r2 = &GTElement::from_bytes(ct.c2()) * &sig.pair(&-ct.c1());
    otp::decrypt(&hash_gt(&r2)[..], ct.c3()).expect("a 32-byte key is always valid")
}

/// Signs `tag` with BasicSchemeMPL, producing the witness that decrypts
/// ciphertexts made for `(sk.public_key(), tag)`.
pub fn sign_tag(sk: &SecretKey, tag: &[u8]) -> Signature {
    let mut sig = hash_to_g2_with_dst(tag, BASIC_SCHEME_DST);
    sig.scalar_multiply(&sk.to_bytes());
    sig
}

fn encrypt_inner(
    pk: &PublicKey,
    tag: &[u8],
    msg: &[u8],
    r1: &[u8],
    s1: &[u8],
    s2: &[u8],
) -> Result<CipherText, Error> {
    if msg.is_empty() {
        return Err(Error::EmptyMessage);
    }
    let mut c1 = PublicKey::generator();
    c1.scalar_multiply(r1);

    let r2 = random_gt(s1, s2);
    let mut h = hash_to_g2_with_dst(tag, BASIC_SCHEME_DST);
    h.scalar_multiply(r1);
    let c2 = &h.pair(pk) * &r2;

    let c3 = otp::encrypt(&hash_gt(&r2)[..], msg)?;
    Ok(CipherText::new(c1, c2.to_bytes(), c3))
}

fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<[u8; SCALAR_SEED_LEN]> {
    let mut bytes = Zeroizing::new([0u8; SCALAR_SEED_LEN]);
    rng.fill_bytes(&mut bytes[..]);
    bytes
}

/// e(s1*G1, s2*G2), the same construction as the C++ `Helpers::RandomGT`.
fn random_gt(s1: &[u8], s2: &[u8]) -> GTElement {
    let mut g1 = PublicKey::generator();
    g1.scalar_multiply(s1);
    let mut g2 = Signature::generator();
    g2.scalar_multiply(s2);
    g2.pair(&g1)
}

fn hash_gt(gt: &GTElement) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(gt.to_bytes()).into())
}
```

Add to `lib.rs`:

```rust
mod scheme;

#[cfg(feature = "test-vectors")]
pub use scheme::encrypt_with_scalars;
pub use scheme::{decrypt, encrypt, encrypt_with_rng, sign_tag, BASIC_SCHEME_DST};
```

**Step 4: Run them and watch them pass**

Run: `cargo test -p witenc --test scheme`

Expected: `test result: ok. 9 passed`.

**Step 5: Run the whole crate's checks**

Run: `cargo test -p witenc && cargo clippy -p witenc --all-targets --all-features -- -D warnings && cargo fmt --check`

Expected: all tests pass, no clippy warnings, no formatting diff. If `fmt --check` reports a diff, run `cargo fmt` and include the result in the commit.

**Step 6: Commit** with the subject `feat: add witness encryption and decryption over chia-bls`.

**Exit check (Phase 2):** `cargo test -p witenc` passes, and clippy and fmt are clean.

---

## Phase 3: Cross-implementation compatibility

### Task 3.1: C++ test-vector tool

**Files:**
- Create: `compat/wevectors.cpp`
- Create: `compat/CMakeLists.txt`
- Create: `compat/README.md`
- Modify: `CMakeLists.txt` (add a `BUILD_WITENC_COMPAT` option)

**Step 1: Write `compat/wevectors.cpp`.** It uses only the library's public API and changes nothing in `src/`.

```cpp
// Emits and checks test vectors so the Rust port can be verified against
// this implementation. Output: one record per line, space-separated
// key=value fields, values in lowercase hex.
#include <algorithm>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "witenc.hpp"

using std::string;
using std::vector;
using namespace witenc;

typedef std::map<string, string> Record;
typedef vector<std::pair<string, string>> Fields;

static Record ParseRecord(const string& line) {
    Record rec;
    std::istringstream in(line);
    string field;
    while (in >> field) {
        size_t eq = field.find('=');
        if (eq != string::npos) {
            rec[field.substr(0, eq)] = field.substr(eq + 1);
        }
    }
    return rec;
}

static void Emit(const Fields& fields) {
    for (size_t i = 0; i < fields.size(); i++) {
        std::cout << (i ? " " : "") << fields[i].first << "=" << fields[i].second;
    }
    std::cout << "\n";
}

static string Hex(const bytes& b) { return Util::HexStr(b); }

// Deterministic bytes: SHA-256(label || be32(i)) blocks, truncated to n.
static bytes Det(const string& label, size_t n) {
    bytes out;
    for (uint32_t i = 0; out.size() < n; i++) {
        bytes in(label.begin(), label.end());
        uint8_t ctr[4];
        Util::IntToFourBytes(ctr, i);
        in.insert(in.end(), ctr, ctr + 4);
        bytes h(32);
        Util::Hash256(h.data(), in.data(), in.size());
        out.insert(out.end(), h.begin(), h.end());
    }
    out.resize(n);
    return out;
}

// Big-endian scalar below the group order, so every implementation
// interprets it the same way regardless of how it reduces.
static bytes DetScalar(const string& label) {
    bytes s = Det(label, 32);
    s[0] &= 0x3f;
    return s;
}

static blst_scalar Scalar(const bytes& be) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, be.data());
    return s;
}

// Mirrors Scheme::Encrypt with caller-supplied randomness.
static CipherText EncryptWith(const G1& pk, const bytes& tag, const bytes& msg,
                              const bytes& r1b, const bytes& s1b, const bytes& s2b) {
    CipherText ct;
    blst_scalar r1 = Scalar(r1b);
    ct.c1 = r1 * G1::Generator();

    blst_scalar s1 = Scalar(s1b);
    blst_scalar s2 = Scalar(s2b);
    G1 g1 = s1 * G1::Generator();
    G2 g2 = s2 * G2::Generator();
    GT r2 = g1.Pair(g2);

    G2 h = G2::FromMessage(tag,
        (const uint8_t*)BasicSchemeMPL::CIPHERSUITE_ID.c_str(),
        BasicSchemeMPL::CIPHERSUITE_ID.length());
    GT pair = pk.Pair(r1 * h);
    GT c2 = pair * r2;
    ct.c2 = c2.Serialize();

    Scheme::BuildC3(ct, r2, msg);
    return ct;
}

static int Kat() {
    const vector<size_t> sizes = {1, 5, 31, 32, 33, 64, 100, 1024};
    const vector<bytes> tags = {bytes{}, bytes{119, 111, 114, 108, 100}, Det("tag", 32)};
    for (size_t t = 0; t < tags.size(); t++) {
        for (size_t size : sizes) {
            string id = std::to_string(t) + "-" + std::to_string(size);
            PrivateKey sk = BasicSchemeMPL().KeyGen(Det("seed" + id, 32));
            G1 pk = sk.GetG1Element();
            G2 sig = BasicSchemeMPL().Sign(sk, tags[t]);
            bytes msg = Det("msg" + id, size);
            if (size == 33) {
                // Zero tail: documents that v1 decryption strips trailing zeros.
                std::fill(msg.end() - 3, msg.end(), 0);
            }
            bytes r1 = DetScalar("r1" + id), s1 = DetScalar("s1" + id), s2 = DetScalar("s2" + id);
            CipherText ct = EncryptWith(pk, tags[t], msg, r1, s1, s2);
            Emit({{"sk", Hex(sk.Serialize())}, {"pk", Hex(pk.Serialize())},
                  {"sig", Hex(sig.Serialize())}, {"tag", Hex(tags[t])}, {"msg", Hex(msg)},
                  {"r1", Hex(r1)}, {"s1", Hex(s1)}, {"s2", Hex(s2)},
                  {"ct", Hex(ct.Serialize())}, {"dec", Hex(Scheme::Decrypt(sig, ct))}});
        }
    }
    return 0;
}

static int RandomEncrypt(int count) {
    for (int i = 0; i < count; i++) {
        string id = std::to_string(i);
        PrivateKey sk = BasicSchemeMPL().KeyGen(Det("rseed" + id, 32));
        G1 pk = sk.GetG1Element();
        bytes tag = Det("rtag" + id, 16);
        G2 sig = BasicSchemeMPL().Sign(sk, tag);
        bytes msg = Det("rmsg" + id, 1 + (i * 37) % 200);
        CipherText ct = Scheme::Encrypt(pk, tag, msg);
        Emit({{"pk", Hex(pk.Serialize())}, {"sig", Hex(sig.Serialize())}, {"tag", Hex(tag)},
              {"msg", Hex(msg)}, {"ct", Hex(ct.Serialize())},
              {"dec", Hex(Scheme::Decrypt(sig, ct))}});
    }
    return 0;
}

static int DecryptStdin() {
    string line;
    while (std::getline(std::cin, line)) {
        Record rec = ParseRecord(line);
        try {
            G2 sig = G2::FromByteVector(Util::HexToBytes(rec.at("sig")));
            bytes ctb = Util::HexToBytes(rec.at("ct"));
            CipherText ct = CipherText::Deserialize(ctb);
            Emit({{"dec", Hex(Scheme::Decrypt(sig, ct))}});
        } catch (const std::exception&) {
            Emit({{"error", "1"}});
        }
    }
    return 0;
}

static int Parse() {
    PrivateKey sk = BasicSchemeMPL().KeyGen(Det("parse-seed", 32));
    bytes valid = EncryptWith(sk.GetG1Element(), Det("parse-tag", 8), Det("parse-msg", 33),
                              DetScalar("p1"), DetScalar("p2"), DetScalar("p3")).Serialize();
    vector<bytes> cases;
    for (size_t n : {0, 1, 47, 48, 49, 623, 624, 625}) {
        cases.push_back(bytes(valid.begin(), valid.begin() + std::min(n, valid.size())));
    }
    cases.push_back(valid);
    bytes flipped = valid;
    flipped[5] ^= 0x01;                       // c1 x-coordinate changed
    cases.push_back(flipped);
    bytes uncompressed = valid;
    uncompressed[0] &= 0x7f;                  // compression flag cleared
    cases.push_back(uncompressed);
    bytes infinity = valid;
    infinity[0] = 0xc0;                       // point at infinity
    std::fill(infinity.begin() + 1, infinity.begin() + 48, 0);
    cases.push_back(infinity);
    bytes junk_c2 = valid;                    // c2 is not validated
    std::fill(junk_c2.begin() + 48, junk_c2.begin() + 48 + 576, 0xff);
    cases.push_back(junk_c2);

    for (bytes& c : cases) {
        bool ok = true;
        try {
            bytes copy = c;
            CipherText::Deserialize(copy);
        } catch (const std::exception&) {
            ok = false;
        }
        Emit({{"ct", Hex(c)}, {"ok", ok ? "1" : "0"}});
    }
    return 0;
}

static int Keystream() {
    for (size_t k : {1, 16, 32}) {
        for (size_t m : {0, 1, 31, 32, 33, 100}) {
            string id = std::to_string(k) + "-" + std::to_string(m);
            bytes key = Det("key" + id, k);
            bytes msg = Det("ksmsg" + id, m);
            bytes enc = OTP::Encrypt(key, msg);
            Emit({{"key", Hex(key)}, {"msg", Hex(msg)}, {"enc", Hex(enc)},
                  {"dec", Hex(OTP::Decrypt(key, enc))}});
        }
    }
    return 0;
}

static int Gt() {
    G1 g1 = G1::Generator();
    G2 g2 = G2::Generator();
    Emit({{"gt", Hex(g1.Pair(g2).Serialize())}});
    return 0;
}

int main(int argc, char* argv[]) {
    string mode = argc > 1 ? argv[1] : "";
    if (mode == "kat") return Kat();
    if (mode == "encrypt") return RandomEncrypt(argc > 2 ? std::stoi(argv[2]) : 20);
    if (mode == "decrypt") return DecryptStdin();
    if (mode == "parse") return Parse();
    if (mode == "keystream") return Keystream();
    if (mode == "gt") return Gt();
    std::cerr << "usage: wevectors kat|encrypt [n]|decrypt|parse|keystream|gt\n";
    return 2;
}
```

**Step 2: Write `compat/CMakeLists.txt`**

```cmake
add_executable(wevectors wevectors.cpp)
target_link_libraries(wevectors PRIVATE witenc)
```

**Step 3: Add the option to the root `CMakeLists.txt`.** Insert after `add_subdirectory(src)`:

```cmake
set(BUILD_WITENC_COMPAT "0" CACHE STRING "Build the wevectors test-vector tool")
if(BUILD_WITENC_COMPAT)
  add_subdirectory(compat)
endif()
```

**Step 4: Build it**

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 -DBUILD_WITENC_COMPAT=1
cmake --build build -j4
./build/compat/wevectors gt | cut -c1-40
```

Expected: a line that starts with `gt=`.

If a C++ API call doesn't compile (for example an operator that takes non-const references), adapt the tool only. Keep the same math and the same output fields, and never change `src/`.

**Step 5: Generate the fixtures**

```bash
mkdir -p compat/vectors
B=./build/compat/wevectors
$B kat > compat/vectors/kat.txt
$B encrypt 20 > compat/vectors/cpp_encrypt.txt
$B parse > compat/vectors/parse.txt
$B keystream > compat/vectors/keystream.txt
$B gt > compat/vectors/gt.txt
wc -l compat/vectors/*.txt
```

Expected line counts: `kat.txt` 24, `cpp_encrypt.txt` 20, `parse.txt` 13, `keystream.txt` 18, `gt.txt` 1.

**Step 6: Write `compat/README.md`**

````markdown
# Compatibility vectors

`wevectors` is a small C++ program that prints test vectors from the reference
C++ implementation. The Rust tests in `crates/witenc/tests/compat.rs` check
against them. Never edit the files in `vectors/` by hand.

Build and regenerate:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 -DBUILD_WITENC_COMPAT=1
cmake --build build -j4
B=./build/compat/wevectors
$B kat > compat/vectors/kat.txt
$B encrypt 20 > compat/vectors/cpp_encrypt.txt
$B parse > compat/vectors/parse.txt
$B keystream > compat/vectors/keystream.txt
$B gt > compat/vectors/gt.txt
```

`cpp_encrypt.txt` uses real randomness, so regenerating it changes its bytes.
The other files are deterministic.

Live round trip (Rust encrypts, C++ decrypts):

```bash
WITENC_CPP_BIN=$PWD/build/compat/wevectors cargo test -p witenc --all-features --test compat -- --ignored
```
````

**Step 7: Commit** `compat CMakeLists.txt` with the subject `test: add C++ test-vector tool and generated v1 fixtures`.

### Task 3.2: Rust compatibility tests

**Files:**
- Modify: `crates/witenc/tests/compat.rs` (replace the placeholder)

**Step 1: Write the tests**

```rust
//! Checks the Rust port against vectors produced by the C++ reference
//! (`compat/wevectors.cpp`). Run with `--all-features`.

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

use witenc::chia_bls::{PublicKey, SecretKey, Signature};
use witenc::{decrypt, encrypt, encrypt_with_scalars, otp, sign_tag, CipherText};

const KAT: &str = include_str!("../../../compat/vectors/kat.txt");
const CPP_ENCRYPT: &str = include_str!("../../../compat/vectors/cpp_encrypt.txt");
const PARSE: &str = include_str!("../../../compat/vectors/parse.txt");
const KEYSTREAM: &str = include_str!("../../../compat/vectors/keystream.txt");
const GT: &str = include_str!("../../../compat/vectors/gt.txt");

type Record = HashMap<String, String>;

fn records(text: &str) -> Vec<Record> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split_whitespace()
                .filter_map(|field| field.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .collect()
}

fn field(r: &Record, key: &str) -> Vec<u8> {
    hex::decode(&r[key]).unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn array<const N: usize>(r: &Record, key: &str) -> [u8; N] {
    field(r, key).try_into().unwrap_or_else(|_| panic!("{key}: wrong length"))
}

fn pk(r: &Record) -> PublicKey {
    PublicKey::from_bytes(&array(r, "pk")).unwrap()
}

fn sig(r: &Record) -> Signature {
    Signature::from_bytes(&array(r, "sig")).unwrap()
}

#[test]
fn gt_encoding_matches_cpp() {
    let gt = Signature::generator().pair(&PublicKey::generator());
    assert_eq!(gt.to_bytes().to_vec(), field(&records(GT)[0], "gt"));
}

#[test]
fn basic_scheme_signatures_match_cpp() {
    for r in records(KAT) {
        let sk = SecretKey::from_bytes(&array(&r, "sk")).unwrap();
        assert_eq!(sk.public_key(), pk(&r));
        assert_eq!(sign_tag(&sk, &field(&r, "tag")), sig(&r));
    }
}

#[test]
fn kat_ciphertexts_match_cpp_byte_for_byte() {
    for r in records(KAT) {
        let ct = encrypt_with_scalars(
            &pk(&r),
            &field(&r, "tag"),
            &field(&r, "msg"),
            &array(&r, "r1"),
            &array(&r, "s1"),
            &array(&r, "s2"),
        )
        .unwrap();
        assert_eq!(ct.to_hex(), r["ct"], "msg={}", r["msg"]);
    }
}

#[test]
fn decrypts_cpp_ciphertexts() {
    for r in records(KAT).iter().chain(records(CPP_ENCRYPT).iter()) {
        let ct = CipherText::from_bytes(&field(r, "ct")).unwrap();
        assert_eq!(decrypt(&sig(r), &ct), field(r, "dec"));
    }
}

#[test]
fn parsing_accepts_and_rejects_like_cpp() {
    for r in records(PARSE) {
        let accepted = CipherText::from_bytes(&field(&r, "ct")).is_ok();
        assert_eq!(accepted, r["ok"] == "1", "ct length {}", r["ct"].len() / 2);
    }
}

#[test]
fn keystream_matches_cpp() {
    for r in records(KEYSTREAM) {
        let key = field(&r, "key");
        let enc = otp::encrypt(&key, &field(&r, "msg")).unwrap();
        assert_eq!(enc, field(&r, "enc"));
        assert_eq!(otp::decrypt(&key, &enc).unwrap(), field(&r, "dec"));
    }
}

#[test]
#[ignore = "needs the C++ reference: set WITENC_CPP_BIN to the wevectors binary"]
fn cpp_decrypts_rust_ciphertexts() {
    let bin = std::env::var("WITENC_CPP_BIN").expect("WITENC_CPP_BIN must be set");
    let kat = records(KAT);
    let mut input = String::new();
    for r in &kat {
        let ct = encrypt(&pk(r), &field(r, "tag"), &field(r, "msg")).unwrap();
        input.push_str(&format!("sig={} ct={}\n", r["sig"], ct.to_hex()));
    }
    let mut child = Command::new(bin)
        .arg("decrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let got = records(std::str::from_utf8(&out.stdout).unwrap());
    assert_eq!(got.len(), kat.len());
    for (g, r) in got.iter().zip(&kat) {
        assert_eq!(field(g, "dec"), field(r, "dec"));
    }
}
```

**Step 2: Run them**

Run: `cargo test -p witenc --all-features --test compat`

Expected: `test result: ok. 6 passed; 0 failed; 1 ignored`.

If anything fails:
- **`gt_encoding_matches_cpp` fails:** the blst internal layouts differ. STOP (condition 3).
- **`basic_scheme_signatures_match_cpp` fails:** check `BASIC_SCHEME_DST` against `BasicSchemeMPL::CIPHERSUITE_ID` in the fetched `bls-src`.
- **`kat_ciphertexts_match_cpp_byte_for_byte` fails while the decrypt tests pass:** the difference is in how randomness is used. Compare `c1`, `c2` and `c3` separately before changing anything.
- **`parsing_accepts_and_rejects_like_cpp` fails on the infinity case:** record the difference in the results file and STOP. Whether to accept the point at infinity is a decision for the author.

**Step 3: Run the live round trip**

Run: `WITENC_CPP_BIN=$PWD/build/compat/wevectors cargo test -p witenc --all-features --test compat -- --ignored`

Expected: `1 passed`.

**Step 4: Commit** `crates/witenc/tests/compat.rs` with the subject `test: verify Rust port against C++ vectors in both directions`.

**Exit check (Phase 3):** every compat test passes, including the ignored live test.

---

## Phase 4: Hardening

### Task 4.1: Property tests

**Files:**
- Create: `crates/witenc/tests/properties.rs`

**Step 1: Write the properties**

```rust
use proptest::collection::vec;
use proptest::prelude::*;
use witenc::chia_bls::{PublicKey, SecretKey};
use witenc::{decrypt, encrypt, otp, sign_tag, CipherText, C1_LEN, C2_LEN};

fn strip_trailing_zeros(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    v
}

proptest! {
    // Pairings are slow, so keep the case count modest.
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn round_trips(seed in any::<[u8; 32]>(), tag in vec(any::<u8>(), 0..64), msg in vec(any::<u8>(), 1..256)) {
        let sk = SecretKey::from_seed(&seed);
        let ct = encrypt(&sk.public_key(), &tag, &msg).unwrap();
        prop_assert_eq!(CipherText::from_bytes(&ct.to_bytes()).unwrap(), ct.clone());
        prop_assert_eq!(decrypt(&sign_tag(&sk, &tag), &ct), strip_trailing_zeros(msg));
    }

    #[test]
    fn wrong_witness_never_reveals_message(seed in any::<[u8; 32]>(), other in any::<[u8; 32]>(), msg in vec(1..=255u8, 16..64)) {
        prop_assume!(seed != other);
        let sk = SecretKey::from_seed(&seed);
        let wrong = SecretKey::from_seed(&other);
        let ct = encrypt(&sk.public_key(), b"tag", &msg).unwrap();
        prop_assert_ne!(decrypt(&sign_tag(&wrong, b"tag"), &ct), msg);
    }
}

proptest! {
    #[test]
    fn from_bytes_never_panics(bytes in vec(any::<u8>(), 0..1400)) {
        let _ = CipherText::from_bytes(&bytes);
    }

    #[test]
    fn from_bytes_with_valid_c1_round_trips(c2 in vec(any::<u8>(), C2_LEN), c3 in vec(any::<u8>(), 1..200)) {
        let mut bytes = PublicKey::generator().to_bytes().to_vec();
        bytes.extend(&c2);
        bytes.extend(&c3);
        let ct = CipherText::from_bytes(&bytes).unwrap();
        prop_assert_eq!(ct.to_bytes(), bytes);
        prop_assert_eq!(ct.to_bytes().len(), C1_LEN + C2_LEN + c3.len());
    }

    #[test]
    fn otp_round_trips(key in vec(any::<u8>(), 1..=32), msg in vec(any::<u8>(), 0..300)) {
        let ct = otp::encrypt(&key, &msg).unwrap();
        prop_assert_eq!(ct.len() % key.len(), 0);
        prop_assert_eq!(otp::decrypt(&key, &ct).unwrap(), strip_trailing_zeros(msg));
    }
}
```

**Step 2: Run them**

Run: `cargo test -p witenc --test properties`

Expected: `test result: ok. 5 passed`.

These test behavior that already exists, so they are expected to pass on the first run. If one fails, proptest prints a minimal failing input. Fix the code, not the property, unless the property contradicts the v1 contract above.

**Step 3: Commit** with the subject `test: add property tests for round trips and parsing`.

### Task 4.2: Fuzz the parser

**Files:**
- Create: `crates/witenc/fuzz/Cargo.toml`
- Create: `crates/witenc/fuzz/fuzz_targets/parse.rs`
- Create: `crates/witenc/fuzz/.gitignore`

**Step 1: Write `crates/witenc/fuzz/Cargo.toml`**

```toml
[package]
name = "witenc-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
witenc = { path = ".." }

[[bin]]
name = "parse"
path = "fuzz_targets/parse.rs"
test = false
doc = false
bench = false
```

**Step 2: Write `crates/witenc/fuzz/fuzz_targets/parse.rs`**

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use witenc::CipherText;

fuzz_target!(|data: &[u8]| {
    if let Ok(ct) = CipherText::from_bytes(data) {
        assert_eq!(ct.to_bytes(), data);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = CipherText::from_hex(text);
    }
});
```

**Step 3: Write `crates/witenc/fuzz/.gitignore`** with these lines: `target`, `corpus`, `artifacts`, `coverage`, `Cargo.lock`.

**Step 4: Fuzz for 10 minutes**

Run: `cd crates/witenc && cargo +nightly fuzz run parse -- -max_total_time=600`

Expected: libFuzzer ends with `Done N runs in 600 second(s)` and no crash.

If it crashes:
- **Round-trip assertion failure:** a non-canonical `c1` encoding (for example the infinity flag with stray bits) was accepted and re-encoded differently. That behavior is inherited from `chia-bls` and the C++. Record it in the results file, change the assertion to compare `CipherText::from_bytes(&ct.to_bytes()).unwrap() == ct`, and run again.
- **Panic inside `witenc`:** fix it with a regression test in `tests/ciphertext.rs` first.
- **Crash inside `chia-bls` or `blst`:** STOP (condition 4).

**Step 5: Commit** `crates/witenc/fuzz` with the subject `test: add cargo-fuzz target for ciphertext parsing`. Note the run length and result in the commit body.

### Task 4.3: Supply-chain checks

**Files:**
- Create: `deny.toml`

**Step 1: Write `deny.toml`**

```toml
[graph]
all-features = true

[advisories]
version = 2

[licenses]
version = 2
allow = [
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BSL-1.0",
  "CC0-1.0",
  "ISC",
  "MIT",
  "Unicode-3.0",
  "Zlib",
]

[licenses.private]
ignore = true

[bans]
multiple-versions = "warn"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

**Step 2: Run it**

Run: `cargo deny check`

Expected: `advisories ok, bans ok, licenses ok, sources ok`. Warnings about duplicate crate versions are acceptable.

If a dependency uses a license that is not in the list:
- **Permissive OSI license:** add it and say so in the commit message.
- **Copyleft, or no license:** record it in the results file and leave the check failing. The author decides.

**Step 3: Commit** `deny.toml` with the subject `build: add cargo-deny configuration`.

**Exit check (Phase 4):**
- `cargo test -p witenc --all-features` passes.
- The fuzz run is clean.
- `cargo deny check` passes.

---

## Phase 5: Python bindings

### Task 5.1: Python environment and failing tests

**Files:**
- Create: `crates/witenc-py/tests/test_witencpy.py`

**Step 1: Create the virtual environment** in the worktree root. `.venv` is already in `.gitignore`.

```bash
uv venv .venv
uv pip install --python .venv/bin/python maturin pytest
```

**Step 2: Write the tests.** Keys and signatures come from the C++ vectors, so no Python BLS library is needed.

```python
"""Tests for the Rust-backed witencpy module.

Keys and signatures come from the C++-generated vectors in compat/vectors,
so no Python BLS library is needed.
"""
import concurrent.futures
import pathlib

import pytest

import witencpy
from witencpy import OTP, CipherText, Scheme

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "compat" / "vectors"


def records(name):
    out = []
    for line in (VECTORS / name).read_text().splitlines():
        if line.strip():
            fields = dict(f.split("=", 1) for f in line.split())
            out.append({k: v if k == "ok" else bytes.fromhex(v) for k, v in fields.items()})
    return out


KAT = records("kat.txt")


def test_round_trip():
    r = KAT[1]
    ct = Scheme.encrypt(r["pk"], r["tag"], r["msg"])
    assert Scheme.decrypt(r["sig"], ct) == r["dec"]


def test_decrypts_cpp_ciphertexts():
    for r in KAT + records("cpp_encrypt.txt"):
        assert Scheme.decrypt(r["sig"], CipherText.from_bytes(r["ct"])) == r["dec"]


def test_serialization_round_trips():
    r = KAT[1]
    ct = Scheme.encrypt(r["pk"], r["tag"], r["msg"])
    assert CipherText.from_bytes(bytes(ct)) == ct
    assert CipherText.from_hex(ct.to_hex()) == ct
    assert len(ct.c1) == 48 and len(ct.c2) == 576
    assert bytes(ct) == ct.c1 + ct.c2 + ct.c3
    ct.validate()


def test_rejects_malformed_input():
    with pytest.raises(ValueError):
        CipherText.from_bytes(b"\x00" * 10)
    with pytest.raises(ValueError):
        Scheme.encrypt(b"\x00" * 47, b"tag", b"msg")
    with pytest.raises(ValueError):
        Scheme.encrypt(KAT[1]["pk"], b"tag", b"")


def test_otp_round_trip_and_key_length():
    key = bytes(range(32))
    assert OTP.decrypt(key, OTP.encrypt(key, b"Hello World!")) == b"Hello World!"
    with pytest.raises(ValueError):
        OTP.encrypt(b"", b"msg")
    with pytest.raises(ValueError):
        OTP.encrypt(bytes(33), b"msg")


def test_concurrent_encryption():
    # Regression for D3: the C++ bindings raced on a global RNG.
    r = KAT[1]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        cts = list(pool.map(lambda _: Scheme.encrypt(r["pk"], r["tag"], r["msg"]), range(64)))
    assert len({bytes(c) for c in cts}) == 64
    assert all(Scheme.decrypt(r["sig"], c) == r["dec"] for c in cts)


def test_version():
    assert witencpy.__version__
```

**Step 3: Run them and watch them fail**

Run: `.venv/bin/python -m pytest crates/witenc-py/tests -q`

Expected: `ModuleNotFoundError: No module named 'witencpy'`.

### Task 5.2: PyO3 module

**Files:**
- Create: `crates/witenc-py/Cargo.toml`
- Create: `crates/witenc-py/pyproject.toml`
- Create: `crates/witenc-py/src/lib.rs`

**Step 1: Write `crates/witenc-py/Cargo.toml`**

```toml
[package]
name = "witenc-py"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
name = "witencpy"
crate-type = ["cdylib"]
test = false
doctest = false

[dependencies]
chia-bls = "0.52"
pyo3 = { version = "0.29", features = ["abi3-py39"] }
witenc = { path = "../witenc" }
```

**Step 2: Write `crates/witenc-py/pyproject.toml`**

```toml
[build-system]
requires = ["maturin>=1.8,<2"]
build-backend = "maturin"

[project]
name = "witencpy"
requires-python = ">=3.9"
dynamic = ["version"]

[tool.maturin]
module-name = "witencpy"
features = ["pyo3/extension-module"]
```

**Step 3: Write `crates/witenc-py/src/lib.rs`**

```rust
//! Python bindings with the same names as the C++ `witencpy` module.

use chia_bls::{PublicKey, Signature};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn value_error(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn public_key(bytes: &[u8]) -> PyResult<PublicKey> {
    let bytes: &[u8; 48] = bytes.try_into().map_err(|_| value_error("public key must be 48 bytes"))?;
    PublicKey::from_bytes(bytes).map_err(value_error)
}

fn signature(bytes: &[u8]) -> PyResult<Signature> {
    let bytes: &[u8; 96] = bytes.try_into().map_err(|_| value_error("signature must be 96 bytes"))?;
    Signature::from_bytes(bytes).map_err(value_error)
}

#[pyclass(name = "CipherText", module = "witencpy", frozen, eq)]
#[derive(Clone, PartialEq)]
struct PyCipherText(witenc::CipherText);

#[pymethods]
impl PyCipherText {
    #[getter]
    fn c1<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.c1().to_bytes())
    }

    #[getter]
    fn c2<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.c2())
    }

    #[getter]
    fn c3<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.c3())
    }

    fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    #[staticmethod]
    fn from_hex(s: &str) -> PyResult<Self> {
        witenc::CipherText::from_hex(s).map(Self).map_err(value_error)
    }

    #[staticmethod]
    fn from_bytes(b: &[u8]) -> PyResult<Self> {
        witenc::CipherText::from_bytes(b).map(Self).map_err(value_error)
    }

    /// Kept for API compatibility; every CipherText is valid by construction.
    fn validate(&self) {}

    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }
}

#[pyclass(name = "Scheme", module = "witencpy", frozen)]
struct PyScheme;

#[pymethods]
impl PyScheme {
    #[staticmethod]
    fn encrypt(py: Python<'_>, pk: &[u8], tag: &[u8], msg: &[u8]) -> PyResult<PyCipherText> {
        let pk = public_key(pk)?;
        let (tag, msg) = (tag.to_vec(), msg.to_vec());
        py.detach(move || witenc::encrypt(&pk, &tag, &msg))
            .map(PyCipherText)
            .map_err(value_error)
    }

    #[staticmethod]
    fn decrypt<'py>(py: Python<'py>, sig: &[u8], ct: PyRef<'_, PyCipherText>) -> PyResult<Bound<'py, PyBytes>> {
        let sig = signature(sig)?;
        let ct = ct.0.clone();
        let msg = py.detach(move || witenc::decrypt(&sig, &ct));
        Ok(PyBytes::new(py, &msg))
    }
}

#[pyclass(name = "OTP", module = "witencpy", frozen)]
struct PyOtp;

#[pymethods]
impl PyOtp {
    #[staticmethod]
    fn encrypt<'py>(py: Python<'py>, key: &[u8], msg: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        witenc::otp::encrypt(key, msg).map(|v| PyBytes::new(py, &v)).map_err(value_error)
    }

    #[staticmethod]
    fn decrypt<'py>(py: Python<'py>, key: &[u8], ct: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        witenc::otp::decrypt(key, ct).map(|v| PyBytes::new(py, &v)).map_err(value_error)
    }
}

#[pymodule]
fn witencpy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyCipherText>()?;
    m.add_class::<PyScheme>()?;
    m.add_class::<PyOtp>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
```

PyO3 naming notes:
- `Python::detach` was called `allow_threads` before PyO3 0.26. If the pinned version doesn't have `detach`, use the name it does have.
- If PyO3 reports that the `extension-module` feature is deprecated, remove that line from `pyproject.toml`.

**Step 4: Build into the venv and run the tests**

```bash
source .venv/bin/activate && cd crates/witenc-py && maturin develop --release && cd ../.. && python -m pytest crates/witenc-py/tests -q
```

Expected: `7 passed`.

**Step 5: Check the Rust side**

Run: `cargo clippy -p witenc-py -- -D warnings && cargo fmt --check`

Expected: clean.

**Step 6: Commit** `crates/witenc-py Cargo.lock` with the subject `feat: add PyO3 bindings with the witencpy API`.

Note these API differences from the C++ module in the commit body:
- Methods return `bytes` instead of `list[int]`; existing `bytes(...)` calls still work.
- `CipherText()` with no arguments is no longer allowed.
- `c1`, `c2` and `c3` are read-only and return `bytes`.
- `from_bytes` is a real static method.
- Errors raise `ValueError`.

### Task 5.3: Port the Python benchmark

**Files:**
- Create: `crates/witenc-py/benchmark.py` (copy of `bindings/python/benchmark.py` with blspy removed)

**Step 1: Copy the file:** `cp bindings/python/benchmark.py crates/witenc-py/benchmark.py`

**Step 2: Replace the import and key setup.** Replace everything from the `from blspy import (` line through `sig: G2Element = BasicSchemeMPL.sign(sk, tag)` with:

```python
import pathlib

from witencpy import (Scheme, CipherText, OTP)

cts = []
numIters = 1000

# Keys come from the C++-generated vectors instead of blspy.
_VECTORS = pathlib.Path(__file__).resolve().parents[2] / "compat" / "vectors" / "kat.txt"
_first = dict(f.split("=", 1) for f in _VECTORS.read_text().splitlines()[0].split())
pk_bytes = bytes.fromhex(_first["pk"])
sig_bytes = bytes.fromhex(_first["sig"])
tag = bytes.fromhex(_first["tag"])
```

Then replace every `bytes(pk)` with `pk_bytes` and every `bytes(sig)` with `sig_bytes`.

**Step 3: Run it**

Run: `source .venv/bin/activate && python crates/witenc-py/benchmark.py`

Expected: timing blocks for encryption, decryption, serialization and OTP, and no assertion errors. Save the output in the results file.

**Step 4: Commit** with the subject `test: port Python benchmark to the Rust bindings`.

**Exit check (Phase 5):** pytest passes (7 tests), and `benchmark.py` runs.

---

## Phase 6: Performance comparison

### Task 6.1: Criterion benchmarks

**Files:**
- Modify: `crates/witenc/benches/scheme.rs` (replace the placeholder)

**Step 1: Write the benchmarks**

```rust
use criterion::{criterion_group, criterion_main, Criterion};
use witenc::chia_bls::SecretKey;
use witenc::{decrypt, encrypt, otp, sign_tag, CipherText};

fn bench(c: &mut Criterion) {
    let sk = SecretKey::from_seed(&[7; 32]);
    let pk = sk.public_key();
    let tag = [1u8; 32];
    let msg = [2u8; 32];
    let sig = sign_tag(&sk, &tag);
    let ct = encrypt(&pk, &tag, &msg).unwrap();
    let hex = ct.to_hex();
    let otp_ct = otp::encrypt(&tag, &msg).unwrap();

    c.bench_function("encrypt", |b| b.iter(|| encrypt(&pk, &tag, &msg).unwrap()));
    c.bench_function("decrypt", |b| b.iter(|| decrypt(&sig, &ct)));
    c.bench_function("to_hex", |b| b.iter(|| ct.to_hex()));
    c.bench_function("from_hex", |b| b.iter(|| CipherText::from_hex(&hex).unwrap()));
    c.bench_function("otp_encrypt", |b| b.iter(|| otp::encrypt(&tag, &msg).unwrap()));
    c.bench_function("otp_decrypt", |b| b.iter(|| otp::decrypt(&tag, &otp_ct).unwrap()));
}

criterion_group!(benches, bench);
criterion_main!(benches);
```

**Step 2: Run both benchmarks on the same machine**

```bash
cargo bench -p witenc --bench scheme
./build/src/webench
```

**Step 3: Record a comparison table in the results file.** Use one row per operation (Encrypt, Decrypt, ToHex, FromHex, OTP encrypt, OTP decrypt) with columns for C++ time, Rust time and the ratio.

If Rust is more than 10% slower on encrypt or decrypt, investigate:
- Check that both sides use the ADX path. For Rust, `cargo build -vv -p witenc 2>&1 | grep -i "portable\|adx"` shows the blst build mode (portable dispatches at run time). For C++, check the compile flags of blst under `build/_deps` for `__ADX__` or `__BLST_PORTABLE__`. Then check whether the CPU supports ADX (`grep -c adx /proc/cpuinfo`).
- Then compare where time goes; the pairing dominates both encrypt and decrypt.
- Write down the explanation; do not fork or patch dependencies.

**Step 4: Commit** with the subject `test: add criterion benchmarks matching webench`.

---

## Phase 7: Wrap-up

### Task 7.1: Document the Rust build

**Files:**
- Modify: `README.md` (add a section after "## Build")

**Step 1: Add this section**

````markdown
## Rust implementation

A Rust port lives in `crates/`. It produces and accepts the same ciphertext
bytes as the C++ library.

```bash
cargo test -p witenc --all-features   # unit, property and C++ compatibility tests
cargo bench -p witenc                 # benchmarks
```

Python bindings (same `witencpy` module name and API):

```bash
uv venv .venv && uv pip install --python .venv/bin/python maturin pytest
source .venv/bin/activate
(cd crates/witenc-py && maturin develop --release)
python -m pytest crates/witenc-py/tests -q
```

See `compat/README.md` for regenerating the C++ test vectors.
````

**Step 2: Commit** with the subject `docs: document the Rust build and Python bindings`.

### Task 7.2: Review

**Step 1:** Request a code review of `git -C $REPO/.worktrees/rust-port diff main...rust-port`, using the superpowers:requesting-code-review skill or the `superpowers:code-reviewer` agent if available. Ask specifically about:
- the decrypt identity;
- scalar handling and RNG use;
- `unsafe` (there should be none in `witenc`);
- whether any behavior differs from the v1 contract.

**Step 2:** Fix confirmed findings, each in its own commit with a test. Record anything left unfixed in the results file.

### Task 7.3: Final verification and results

**Step 1: Run everything once more**

```bash
cd $REPO/.worktrees/rust-port
cargo test -p witenc --all-features
WITENC_CPP_BIN=$PWD/build/compat/wevectors cargo test -p witenc --all-features --test compat -- --ignored
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check
cargo deny check
source .venv/bin/activate && python -m pytest crates/witenc-py/tests -q
cd $REPO/.worktrees/cpp-fixes && ./build/src/wetest && ./build-asan/src/wetest
```

Expected: everything passes.

**Step 2: Confirm nothing left the machine**

```bash
git -C $REPO branch -vv
git -C $REPO status --short
```

Expected:
- `fix/cpp-rng-and-parse` and `rust-port` show no `[origin/...]` upstream.
- `main` is unchanged at its starting commit.
- Status shows only `?? .docket/`.

**Step 3: Finish the results file** (`$REPO/.docket/wrap-ups/2026-10-20-rust-port-results.md`) with these sections:
- Summary.
- Branches and commit lists (`git log --oneline main..<branch>`).
- Toolchain versions.
- Baseline and comparison benchmarks.
- Fuzzing result.
- Any differences from this plan, with reasons.
- Unresolved findings.
- Decisions needed from the author, including:
  - whether to merge;
  - whether to start format v2;
  - whether to remove the C++ implementation;
  - whether the point at infinity should be accepted as `c1`.

**Step 4:** Leave both worktrees in place for review. Do not merge, push or delete anything.
