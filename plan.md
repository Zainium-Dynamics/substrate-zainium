# Substrate Architectural Roadmap

## Overview

`substrate` is the official package builder for Zainium OS (`.zex` format).

This document outlines the operational specification and future multi-format export capabilities for `.zex` packages.

## Core Package Pipeline (

1. **Source Inspection**: Validates payload structure and manifest configuration.
2. **Security Integrity Passes**: Unconditional root policy validation (`/usr` merge rejection) and hardcoded secret scanning.
4. **Cryptographic Sealing**: Ephemeral Ed25519 signature generation and deterministic Blake3 hashing over manifest & payload.
5. **Archive Packaging**: Native `zexc` (ZEX1 stream format) compression.

## Target Export Formats (Roadmap)

- **Plain Tarball** (`.tar.gz` / `.tar.zst`): Raw payload container.
- **Alpine `.apk`**: Alpine package format with `.PKGINFO` generation.
- **Arch `.pkg.tar.zst`**: Arch Linux compatible container.
- **Debian `.deb`**: Control & data tarball structure wrapped in `ar`.

## CLI Interface Reference

```bash
substrate pack -v 2.0.0 ./my-package -o my-package-2.0.0.zex
substrate verify my-package-2.0.0.zex
substrate unpack my-package-2.0.0.zex -o ./extracted
substrate inspect my-package-2.0.0.zex
```
