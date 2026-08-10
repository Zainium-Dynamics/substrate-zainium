# substrate

**substrate** turns a build output directory into a signed, tamper-evident package (`.zex`), plus a companion source-review artifact (`.zex.locked`) for whoever needs to look at what a package was built from before it ships.

It was built for [Zainium OS](https://zainiumdynamics.tech)'s package format, but the design isn't Zainium-specific — anyone can use it to build, sign, and verify their own packages. It's open source (MIT) and free to fork, adapt, or point at a different install-path convention.

## Why

Most package formats either trust whoever built the artifact (no signing) or require a persistent, centrally-managed signing key (which becomes a single point of failure — leak it once and every past release is suspect). substrate does neither:

- Every `pack` run generates a **fresh, ephemeral Ed25519 keypair**, signs the payload with it, embeds the public half in the package, and throws the private half away. Nothing durable ever holds a signing key, so there's nothing to leak.
- Every package embeds a **Blake3 hash over its own payload**, computed in a deterministic sorted order, so tampering after the fact is detectable without trusting any external registry.
- A **security pass runs on every build, unconditionally** — layout policy, hardcoded-secrets scan, Rust/C static analysis — and blocks the build outright on failure. Not a warning, not opt-in.
- The `.zex.locked` companion artifact carries the **real source a package was built from**, separately from the compiled output, so a reviewer can look at what something actually is before trusting it — without needing to reproduce the build themselves.

## Install

```
git clone <this repo>
cd substrate
cargo build --release
```

The binary is `target/release/substrate`.

## Quick start

```
substrate pack -v 1.0.0 ./my-package -o my-package-1.0.0.zex
```

`./my-package` needs a `manifest.toml` (package metadata) and a `payload/` directory (the files that actually get installed). This produces:

- `my-package-1.0.0.zex` — the package. Signed, hashed, ready to distribute.
- `my-package-1.0.0.zex.locked` — the review artifact: real source, an audit summary, and a `REVIEW.md` checklist. Never shipped to end users.
- `my-package-1.0.0.receipt.toml` / `.spdx.json` — install receipt and SPDX SBOM.

```
substrate verify my-package-1.0.0.zex        # check the signature, nothing else
substrate unpack my-package-1.0.0.zex -o out # extract payload/ with correct file modes
substrate inspect my-package-1.0.0.zex       # manifest + embedded security report
```

Full command reference, all flags, and the `manifest.toml` schema: see [USAGE.md](USAGE.md).

## Format at a glance

```
package-1.0.0.zex           (zexc-compressed tar, magic ZEX1)
├── manifest.toml            ← name/version/deps/install-map + blake3/ed25519 signature
├── signature.b3              ← blake3(manifest bytes ++ payload blake3)
└── payload/                   ← the actual files, laid out to match manifest.toml's install map

package-1.0.0.zex.locked    (ZEXL-prefixed, separate compressed tar)
├── manifest.toml             ← the same signed manifest, for reference
├── REVIEW.md                  ← audit summary + reviewer checklist
├── header.toml                  ← ledger-ready metadata (what a registry would index)
├── security.toml                 ← full security report
├── receipt.toml                   ← install receipt
└── source/                         ← real upstream source, if `--source <path>` was given
```

`payload/` is deliberately not in `.zex.locked` — reviewing a package means looking at what it was built *from*, not a second copy of the build output.

## License

MIT. Use it, fork it, point it at whatever install-path convention your own project needs.
