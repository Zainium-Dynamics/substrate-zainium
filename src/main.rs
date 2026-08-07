//! substrate — standalone package builder and verifier for `.zex` packages.
//!
//! Originally extracted as a byte-identical copy of `zex fmt` (the
//! `cmd/fmt/` subcommand inside the full `zex` CLI), now developed forward
//! independently under its own name: ephemeral per-build signing (no key
//! ever persisted, see `app.rs::cmd_pack`), oxipatch ELF interpreter/RPATH
//! patching folded into packing itself, and a unified `.zex.locked`
//! artifact that carries both the ledger-ready package header and the
//! maintainer-review workflow. Not wired back into `zex` — `cmd/fmt/`
//! there stays on the older model.
//!
//! Why standalone: packaging is a build-machine concern, not a Zainium-OS
//! runtime concern. A maintainer building `.zex` packages doesn't need
//! (and, on a non-Zainium build machine like Fedora, can't sensibly run)
//! the rest of `zex` — install, remove, upgrade, rollback all assume a
//! live Zainium system (`/overlayer/` union mounts, syshub, etc.) that
//! simply doesn't exist on a generic Linux box used only for building
//! packages.

mod app;
mod cli;
mod core;
mod error;
mod security;
mod ui;
mod utils;
mod zex_codec;

pub use app::run;

fn main() {
    // Without this, every `log::warn!` in the codebase (e.g. the "no
    // signing key found, using dev key" warning in app.rs) is a silent
    // no-op — there's no logger backend unless something initializes
    // one. The full `zex` CLI never calls this either (pre-existing gap
    // there, not something introduced here), but a standalone tool
    // someone runs directly on their own machine should actually show
    // its warnings rather than swallow them.
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    run(args);
}
