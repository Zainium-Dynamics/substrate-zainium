# substrate — usage

## `substrate pack <directory> -v <version>`

Builds `<directory>` into a `.zex` package (plus its `.zex.locked` companion).

`<directory>` must contain:

- `manifest.toml` — package metadata (see `manifest.toml` layout below). If absent, one is generated from the flags below.
- `payload/` — the files that get installed, laid out under `bin/`, `lib/`, `sbin/`, `share/`, `hooks/` matching `manifest.toml`'s `[install]` table.

| Flag | Default | Meaning |
|---|---|---|
| `-v, --version <version>` | required | Package version. Overrides `manifest.toml`'s `package.version`. |
| `--description <text>` | `""` | Overrides `manifest.toml`'s `package.description` (only if non-empty). |
| `--features <a,b,c>` | `""` | Comma-separated feature list. |
| `--requires-syshub <value>` | current year, e.g. `2026` | Required syshub release. Always overrides `manifest.toml`'s field — there's no "compute the right value" logic beyond the year default, so pass this explicitly if the package needs a specific syshub release. |
| `--source <path>` | none | Real upstream source tree this package was compiled from, if it lives outside `<directory>` (e.g. `<directory>` is a build/output subdir of a much larger checkout). Embedded into `.zex.locked` under `source/` — never touches the `.zex`. `<directory>` is pruned out of the walk if it's nested inside this path, so `payload/` never gets double-embedded. |
| `--install-root <path>` | `/overlayer/zexlib` | Union-layer root used to render absolute paths in the install receipt. Rarely needs changing. |
| `--report` | `false` | (reserved) |
| `-o, --output <path>` | `<name>-<version>.zex` | Output path for the `.zex`. Hyphen-separated, matching the Zainium ledger naming convention (e.g. `vim-9.1.1366.zex`) — not an underscore. The `.zex.locked` and other sidecars are derived from this path. |

Output files (all next to `-o`'s path):

- `<out>.zex` — the package.
- `<out>.zex.locked` — review artifact (see README for contents).
- `<out>.receipt.toml` — install receipt (also embedded in `.zex.locked`).
- `<out>.spdx.json` — SPDX SBOM.

Example:

```
substrate pack -v 2.3.0 --requires-syshub 2026 ./build/myapp -o myapp-2.3.0.zex
```

With an external source tree — e.g. `<directory>` (`./build/gcc-musl`) is just the
manifest.toml + payload/ staging dir, and the real compiled-from source lives in a
sibling checkout (`/src/gcc-16`):

```
substrate pack -v 16.0 --requires-syshub 2026 \
  --source /src/gcc-16 \
  ./build/gcc-musl \
  -o gcc-musl-16.0.zex
```

## `substrate unpack <file> -o <dir>`

Works on either a `.zex` or a `.zex.locked` file — detected automatically from the file's magic bytes.

- **`.zex`**: verifies the Ed25519 signature (hard requirement, not optional), extracts `payload/`'s contents into `<dir>` with correct file modes, writes `<dir>/security-report.json`.
- **`.zex.locked`**: extracts `manifest.toml`, `REVIEW.md`, `header.toml`, `security.toml`, `receipt.toml`, and `source/` (if present) into `<dir>`. No signature check here — a `.zex.locked`'s integrity is the maintainer review flow itself, not a per-file signature.

| Flag | Meaning |
|---|---|
| `-o, --output <dir>` | Destination directory. Defaults to the package name (`.zex`) or `<name>-<version>-review` (`.zex.locked`). |
| `--verify-only` | Check the signature (`.zex`) or parse the header (`.zex.locked`) without extracting anything. |

```
substrate unpack myapp_2.3.0.zex -o ./extracted
substrate unpack myapp_2.3.0.zex.locked -o ./review-tree
```

## `substrate verify <file>`

Shorthand for `substrate unpack <file> --verify-only`.

## `substrate inspect <file>`

Prints the manifest, embedded security report, and (if a `.zex.locked` sits next to the `.zex`) the maintainer review status — without extracting anything.

```
substrate inspect myapp_2.3.0.zex
```

## `substrate review <locked_file> --reviewer <id> --status <status>`

Records the single maintainer decision on a `.zex.locked` artifact by rewriting its JSON header in place. This is the offline/local equivalent of the website's Approve button.

| Flag | Meaning |
|---|---|
| `locked_file` | Path to the `.zex.locked` file (positional). |
| `--reviewer <id>` | Reviewer identifier, e.g. `alice@zainium.org`. |
| `--status <status>` | One of `approved`, `changes-requested`, `rejected`. |
| `--notes <text>` | Optional free-text notes. |

```
substrate review myapp_2.3.0.zex.locked --reviewer alice@zainium.org --status approved
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
