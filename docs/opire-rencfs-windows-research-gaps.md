# Research: Windows Support for rencfs — Licensing, Build Shape, NTFS Metadata, CI & Acceptance Criteria

**Bounty:** Opire — "research implementation for Windows" ($42), project `radumarias/rencfs`, issue #3
**Date:** 2026-10-19
**Type:** Research document (no code). Complements, does not duplicate, the existing research in PR #53 (`docs/opire-rencfs-windows-research.md`), which covers the Linux architecture, the WinFSP/Dokany/ProjFS comparison, and the callback→`EncryptedFs` mapping table. This document covers the gaps: **license checkpoint, dependency/build shape, NTFS metadata decisions, CI plan, smoke test, acceptance criteria.**

> Convention: **(verified)** = checked against a primary source cited in §7. **(analysis)** = engineering judgment. **(unknown)** = could not verify.

---

## 1. WinFsp licensing checkpoint for an MIT/Apache-2.0 project

**Status: viable, with one verification step remaining.**

- WinFsp is **GPLv3 with a FLOSS (Free/Libre and Open Source Software) exception** (verified from winfsp.dev). The exception's documented intent: FLOSS-licensed software may link against WinFsp **without** the combined work being forced under GPLv3 (verified from secondary summaries of the exception).
- rencfs is tri-licensed **Apache-2.0 / MIT / BSD-3-Clause** (verified from repo README). Both MIT and Apache-2.0 are OSI-approved FLOSS licenses; Apache-2.0 is explicitly GPLv3-compatible, MIT is GPL-compatible (analysis, standard license-compatibility knowledge).
- **Conclusion (analysis):** under the FLOSS exception, rencfs can link WinFsp and keep its own license. No commercial license needed for the open-source distribution.
- **Commercial fallback (verified from https://winfsp.dev/com/):** organizations $6,000 / 3 years, individuals $2,400 / 3 years — only needed if rencfs ever ships a closed-source edition.
- **Attribution checkpoint (action item for maintainer):** the final implementation PR should (1) quote the **verbatim** FLOSS exception text from the WinFsp distribution (`License.txt` / exception addendum — I could not retrieve the verbatim text, only summaries), (2) add a `NOTICE`/attribution note in the repo crediting WinFsp, (3) document the WinFsp version pinned (WinFsp 2025 = v2.1, installer `winfsp-2.1.25156.msi`, verified from GitHub releases).
- **Comparison (verified):** Dokany is LGPLv3 (driver/user-mode lib) + MIT (control program/samples) — LGPL permits dynamic linking without a paid license, so Dokany is the license-simpler fallback, at the cost of a smaller ecosystem. ProjFS/CfAPI are in-box Microsoft APIs (no third-party license at all) but are **not full filesystems** — ProjFS is a projection/hydration model and cannot implement arbitrary encrypted-FS semantics (verified).

---

## 2. Windows-only dependency and delay-load build shape

**Recommended (analysis):** gate everything Windows-specific so non-Windows builds never see the dependency.

```toml
# Cargo.toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = "0.13"          # tracks WinFsp 2.1 (verified: v0.13.1+winfsp-2.1 on lib.rs)
```

```rust
// src/mount.rs
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::{MountHandleInnerImpl, MountPointImpl};
// existing linux/dummy arms unchanged
```

**Delay-load consideration (analysis):** WinFsp's user-mode DLL (`winfsp-x64.dll`) is only present on machines where the user installed the WinFsp MSI. Two shapes:

1. **Hard link (simplest):** the `winfsp` crate links against the import library at build time; at runtime the DLL must be on the loader path or the process fails to start. Acceptable if the installer/docs make WinFsp a prerequisite (same as Dokany's model).
2. **Delay-load (nicer UX):** load `winfsp-x64.dll` via `LoadLibrary` at mount time and fail gracefully with "WinFsp not installed — see <docs link>" instead of a loader error. Rust has no stable `#[link(kind = "raw-dylib")]` delay-load story as clean as MSVC's `/DELAYLOAD`; the practical approach is a tiny `build.rs` on Windows that links with `/DELAYLOAD:winfsp-x64.dll` + `delayimp.lib`, or manual `LoadLibrary`/`GetProcAddress` in a shim. **Recommendation:** start with (1); add (2) only if startup-UX complaints appear. Document the MSI prerequisite prominently.

**Driver distribution (verified):** end users must install the WinFsp MSI (`winfsp-2.1.25156.msi`, SHA256 published on GitHub releases). The rencfs release docs/installer should bundle or link it. WinFsp supports Windows 7 → 11, x86/x64/ARM64 (verified from winfsp.dev) — no further driver work needed from rencfs.

---

## 3. Windows metadata decisions and unsupported NTFS features (first milestone)

Decisions are for **milestone 1** (truthful, minimal). Anything deferred must be documented as unsupported, not silently wrong.

| Windows concept | Milestone-1 decision (analysis) | Rationale |
|---|---|---|
| File attributes (`READONLY`, `HIDDEN`, `SYSTEM`, `DIRECTORY`) | Translate `owner_write` bit ↔ `FILE_ATTRIBUTE_READONLY`; always set `DIRECTORY` for dirs; ignore the rest | Windows has attributes, not Unix mode bits; minimal truthful mapping |
| Timestamps (creation/access/write/change) | Map `FileAttr::{atime, mtime, ctime}` to write/access/change; synthesize creation time = ctime | rencfs `FileAttr` has no birthtime; document the synthesis |
| **Alternate Data Streams (ADS)** | **Not supported in M1** — reject named-stream opens with a clear error | FUSE has no ADS concept; silently dropping ADS loses data (browsers store `Zone.Identifier` there). WinFsp surfaces streams via `StreamInfo` — wire it in M2 or later |
| **Reparse points** (symlinks, junctions) | **Not supported in M1** — return "not supported" on `GetReparsePoint`/`SetReparsePoint` | rencfs Linux adapter's symlink story must be designed first; wrong reparse data corrupts Explorer |
| Case sensitivity | **Case-insensitive lookup in the adapter** (normalize before `find_by_name`) | Windows is case-insensitive/case-preserving by default; encrypted namespace is case-sensitive — without normalization, `Foo.txt` vs `foo.txt` collide |
| Security descriptors / ACLs | Synthesize a permissive-but-sane default descriptor (owner = full control) | `get_security_by_name` is **mandatory** in WinFsp; rencfs stores Unix-style attrs. Full ACL fidelity is out of scope for M1. **Known bug class (verified from WinFsp 1.10 release notes):** when user SID == group SID (Microsoft-account logins), owner+group modes were combined most-restrictive-wins — test this login shape explicitly |
| Max path / reserved names | Enforce `MAX_PATH`-aware handling; reject Windows-reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, trailing dots/spaces) at create time | Encrypted names are base64-family (ASCII-safe, verified in PR #53) but Windows forbids these names regardless of encoding |
| Sparse files, compression, encryption (EFS) | **Not supported in M1** | Out of scope; document |
| File IDs / inode numbers | Carry rencfs `ino: u64` in the WinFsp file context; expose as 128-bit file ID where the API requires it | Matches the existing adapter pattern (PR #53 §3.2) |

---

## 4. Build / CI plan

**Current state (verified from repo):** no Windows target in CI; `fuse3` is already gated under `[target.'cfg(target_os = "linux")'.dependencies]` — mirror that pattern for `winfsp`.

```yaml
# .github/workflows/ci.yml — add
build-windows:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - name: Install WinFsp
      run: |
        # WinFsp MSI install on the runner (needed for link + any mount test)
        choco install winfsp -y   # or download winfsp-2.1.25156.msi from GitHub releases
    - run: cargo build --locked
    - run: cargo test --locked --lib   # EncryptedFs unit tests are platform-independent
```

**Notes (analysis):**
- Mount round-trip tests on CI are possible (WinFsp installs on `windows-latest` runners) but mount/unmount in CI is flaky-prone; gate them behind an env flag (e.g. `RENcFS_WIN_MOUNT_TESTS=1`) and keep them `#[ignore]` by default.
- MSRV is 1.75 (verified from repo) — confirm the `winfsp` crate's MSRV is ≤ 1.75 before pinning, or document the bump.
- `keyring` 2.3.2 claims Windows Credential Manager support — **verify on a real Windows host** (flagged in PR #53 §3.2 Phase 3).
- `shush-rs` `mlock`/`mprotect` equivalents on Windows — **verify**; if unsupported, secret-memory hardening is reduced on Windows and the README's security posture must say so.

---

## 5. Manual smoke test (Windows host with WinFsp installed)

Run on Windows 10/11, WinFsp 2.1 MSI installed, from an elevated-or-not prompt as documented:

1. `rencfs --data-dir C:\rencfs-data X:` (or directory mount point) → mount succeeds, drive appears in Explorer.
2. Create `hello.txt` via Notepad → read back identical bytes (round-trip through encrypt/decrypt).
3. Copy a 100 MB file in, copy back out → byte-identical (`fc /b`).
4. Rename, delete (including delete-while-open — must follow Windows delete-on-close semantics, not POSIX `unlink`).
5. Unicode names (`日本語.txt`), long paths (>260 chars with long-path opt-in), trailing-dot name (must be rejected per §3).
6. Concurrent writes from two processes to different files → no corruption.
7. Unmount cleanly; remount → all data intact (WAL replay path exercised).
8. Log in with a **Microsoft account** (user SID == group SID) and repeat 2–4 — regression check for the WinFsp 1.10 ACL bug class.

---

## 6. Acceptance criteria for a truthful first implementation PR

1. `cargo build --locked` and `cargo test --locked` pass on `windows-latest` CI (new job, §4).
2. New `src/mount/windows.rs` implements the existing `MountPoint` trait; `mount.rs` gains the `#[cfg(target_os = "windows")]` arm; Linux build is byte-identical in behavior (no `cfg` leakage).
3. Every §3 "Not supported in M1" item returns a **clear, documented error** — never silent data loss or corruption.
4. README/documents: WinFsp MSI prerequisite, license attribution note (§1), M1 limitations list (§3), smoke-test results from a real Windows host (§5).
5. No `unsafe` beyond what the `winfsp` crate requires; no new warnings (`-D warnings` parity with the repo's existing lints).
6. The PR description states plainly what was **not** tested (e.g., "no ARM64 Windows host available") — matching the repo's existing honesty bar (README: "do not use with sensitive data", unaudited).

---

## 7. Sources

- rencfs repo (README: tri-license Apache-2.0/MIT/BSD-3-Clause, "implement it also on macOS and Windows", unaudited warning; `src/mount.rs`, `src/mount/linux.rs`, `src/encryptedfs.rs`, `Cargo.toml` MSRV 1.75, `fuse3` 0.8.1 Linux-gated): https://github.com/radumarias/rencfs
- PR #53 research (Linux architecture, WinFSP/Dokany/ProjFS comparison, callback mapping table, challenges): https://github.com/radumarias/rencfs/pull/53/files
- WinFsp project (FUSE for Windows, driver+DLL architecture, FSP_FSCTL_TRANSACT, FUSE 2.8/3.2 layer, Win 7–11, x86/x64/ARM64): https://winfsp.dev/
- WinFsp 2025 v2.1 release (`winfsp-2.1.25156.msi`, SHA256 on GitHub releases): https://github.com/winfsp/winfsp/releases
- WinFsp licensing/commercial ($6,000 org / $2,400 individual per 3 years, billziss at navimatics.com): https://winfsp.dev/com/
- `winfsp` Rust crate v0.13.1+winfsp-2.1 (~9.8K downloads, `FileSystemContext`, `AsyncFileSystemContext`, `FileInfo`, `DirBuffer`, `StreamInfo`, `U16CString`): https://lib.rs/crates/winfsp and https://docs.rs/winfsp/
- WinFsp 1.10 release notes (user SID == group SID ACL bug class): WinFsp GitHub releases
- Dokany licensing (LGPLv3 driver/lib + MIT control/samples): https://github.com/dokan-dev/dokany
- ProjFS (projection/hydration only, Win 10 1809+, `Client-ProjFS` optional feature): Microsoft docs
- Cloud Files API (`cldflt.sys`, placeholder/hydration model): Microsoft docs
