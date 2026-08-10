# substrate — usage

## `substrate pack <directory> -v <version>`

Builds `<directory>` into a `.zex` package. That's the only output — no sidecar files.

`<directory>` must contain:

- `manifest.toml` — package metadata (see `manifest.toml` layout below). If absent, one is generated from the flags below.
- `payload/` — the files that get installed, laid out under `bin/`, `lib/`, `sbin/`, `share/`, `hooks/` matching `manifest.toml`'s `[install]` table.

| Flag | Default | Meaning |
|---|---|---|
| `-v, --version <version>` | required | Package version. Overrides `manifest.toml`'s `package.version`. |
| `--description <text>` | `""` | Overrides `manifest.toml`'s `package.description` (only if non-empty). |
| `--features <a,b,c>` | `""` | Comma-separated feature list. |
| `--requires-syshub <value>` | current year, e.g. `2026` | Required syshub release. Always overrides `manifest.toml`'s field — there's no "compute the right value" logic beyond the year default, so pass this explicitly if the package needs a specific syshub release. |
| `--install-root <path>` | `/overlayer/zexlib` | Union-layer root used to render install paths only when `<directory>` has no `manifest.toml` of its own (auto-generated case). A real `manifest.toml` ignores this — its own `[install]` map wins. |
| `--report` | `false` | Also write `<out>.security-report.json` — the same report embedded in the `.zex`, dumped to disk for tooling that wants it separately. |
| `-o, --output <path>` | `<name>-<version>.zex` | Output path. Hyphen-separated, matching the Zainium ledger naming convention (e.g. `vim-9.1.1366.zex`) — not an underscore. |

Example:

```
substrate pack -v 2.3.0 --requires-syshub 2026 ./build/myapp -o myapp-2.3.0.zex
```

## `substrate unpack <file> -o <dir>`

Verifies the Ed25519 signature (hard requirement, not optional), extracts `payload/`'s contents into `<dir>` with correct file modes, writes `<dir>/security-report.json`.

| Flag | Meaning |
|---|---|
| `-o, --output <dir>` | Destination directory. Defaults to the package name. |
| `--verify-only` | Check the signature without extracting anything. |

```
substrate unpack myapp_2.3.0.zex -o ./extracted
```

## `substrate verify <file>`

Shorthand for `substrate unpack <file> --verify-only`.

## `substrate inspect <file>`

Prints the manifest and embedded security report without extracting anything.

```
substrate inspect myapp_2.3.0.zex
```

## `substrate keygen -o <path>`

Generates a standalone Ed25519 keypair and writes the 32-byte hex secret key to `<path>`. **Not used by `pack`** — every pack run generates and signs with its own fresh, ephemeral keypair internally and never persists it. This subcommand exists only for anyone who separately needs a real, reusable keypair.

| Flag | Default | Meaning |
|---|---|---|
| `-o, --output <path>` | `signing.key` | Where to write the secret key. |
| `--force` | `false` | Overwrite an existing key file. |

## `manifest.toml` layout

```toml
[package]
name             = "myapp"
version          = "1.0.0"
description      = "..."
license          = "MIT"
maintainer       = "Name <email>"
homepage         = "https://..."
build_type       = "dynamic"          # or "static"
libc_target      = "musl"

blake3           = ""                 # filled in by `substrate pack`
ed25519_sig      = ""                 # filled in by `substrate pack`
ed25519_pubkey   = ""                 # filled in by `substrate pack`

requires_syshub  = ""                 # overridden by --requires-syshub
depends          = ["musl"]
provides         = ["myapp"]
tags             = ["utility"]

[install]
bin     = "/overlayer/zexlib/union/bin"
lib     = "/overlayer/zexlib/union/lib"
share   = "/overlayer/zexlib/union/share"
_syshub = false                       # true only for base-OS packages

[remove]
files    = []                         # filled in by the installer
dirs     = []
symlinks = []

[hooks]
# post_install = "payload/etc/myapp/post-install.sh"
# pre_remove   = "payload/etc/myapp/pre-remove.sh"
```
