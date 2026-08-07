# substrate

Standalone package builder/verifier for Zainium `.zex` packages — pack, unpack, verify, inspect, review.

`substrate` turns a build output directory into a signed, tamper-evident `.zex` package, plus a companion `.zex.locked` artifact for human review before publishing.

## Install

```
cargo build --release
```

The binary is `target/release/substrate`.

## Quick start

```
substrate pack -v 1.0.0 ./my-package -o my-package-1.0.0.zex
```

`./my-package` must contain a `manifest.toml` and a `payload/` directory (the files that actually get installed). This produces two files:

- `my-package-1.0.0.zex` — the package itself, signed and ready to ship.
- `my-package-1.0.0.zex.locked` — a review artifact: the real source this was built from, a security audit summary, and a `REVIEW.md` checklist. Never shipped to end users.

See [USAGE.md](USAGE.md) for the full command reference.

## The two file formats

**`.zex`** — `manifest.toml` + `signature.b3` + `payload/`, tar'd and compressed with the native `zexc` codec (magic `ZEX1`). Every file is Blake3-hashed and Ed25519-signed with a fresh, ephemeral keypair generated at pack time (never persisted, never reused). This is the only thing installers and end users ever touch.

**`.zex.locked`** — `ZEXL` magic + a JSON header (schema, package identity, security report, ledger metadata, review status) + a compressed tar containing:

```
manifest.toml   ← the same signed manifest shipped in the .zex
REVIEW.md       ← human review checklist + audit summary
header.toml     ← [package.<name>] = ledger-ready fields (what zex-server
                   merges into zex_ledger-x86_64.toml on approval)
security.toml   ← the full security report (layout, secrets scan, audits)
receipt.toml    ← install receipt
source/         ← the real upstream source tree, if --source was given
```

`payload/` (the compiled binaries) is deliberately left out of `.zex.locked` — a reviewer looks at what something was built *from*, not a second copy of the build output.

## Security passes (always on, not configurable)

Every `substrate pack` run:

1. Enforces the no-`/usr`-merge layout policy.
2. Scans all text files for hardcoded secrets — blocks the build if any are found.
3. Runs a Rust audit (`cargo audit`-style) when the payload is Rust.
4. Runs a C/C++ audit (`cppcheck` + `clang-tidy`) when the payload has C/C++ sources outside `payload/`.
5. Blake3-hashes and Ed25519-signs the payload.

None of this is optional — a pack that fails any check is blocked, not just warned.
