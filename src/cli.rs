use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "substrate", about = "Zainium Secure Package Format Tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a secure .zex package from a directory.
    /// By default also emits `<out>.zex.locked` (real source + REVIEW.md +
    /// header.toml + security.toml + receipt.toml) — skip it with
    /// --no-locked (e.g. CI publish runs where review already happened
    /// via merge request, not a `.zex.locked` review artifact).
    Pack {
        directory: PathBuf,

        #[arg(short = 'v', long = "version")]
        version: String,

        #[arg(long, default_value = "")]
        description: String,

        #[arg(long, value_delimiter = ',', default_value = "")]
        features: Vec<String>,

        /// Required syshub release this package targets. Defaults to the
        /// current calendar year (e.g. "2026") if omitted — always
        /// overrides whatever's in manifest.toml, same as --version.
        #[arg(long)]
        requires_syshub: Option<String>,

        /// Real source tree this package was compiled from, if it lives
        /// outside `directory` (e.g. an upstream checkout with `directory`
        /// as a build/output subdir of it). Embedded into `.zex.locked`
        /// under `source/` for reviewers — never touches the `.zex` itself.
        /// `directory` is pruned out of the walk if it's nested inside this
        /// path, so payload/ is never double-embedded.
        #[arg(long)]
        source: Option<PathBuf>,

        /// Skip generating `<out>.zex.locked`. Use in CI/publish flows
        /// where review already happened elsewhere (e.g. a GitLab merge
        /// request) — the .zex.locked review artifact is unneeded there.
        #[arg(long, default_value_t = false)]
        no_locked: bool,

        #[arg(long, default_value_t = false)]
        report: bool,

        /// Union-layer root used to render absolute paths in the
        /// install receipt .toml (rarely needs changing).
        #[arg(long, default_value = "/overlayer/zexlib")]
        install_root: String,

        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },

    /// Extract a .zex package, or a .zex.locked review tree (includes REVIEW.md)
    Unpack {
        file: PathBuf,

        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        verify_only: bool,
    },

    /// Verify signature and integrity of a .zex package
    Verify { file: PathBuf },

    /// Show detailed package information
    Inspect { file: PathBuf },

    /// Generate a standalone Ed25519 keypair and print both halves.
    /// NOT used by `pack` — every pack run generates and signs with its
    /// own fresh, ephemeral keypair internally and never persists it;
    /// this subcommand is only for anyone who separately needs a real
    /// keypair for some other purpose.
    Keygen {
        /// Where to write the 32-byte hex secret key.
        #[arg(short = 'o', long = "output", default_value = "signing.key")]
        output: PathBuf,

        /// Overwrite an existing key file if one is already there.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}
