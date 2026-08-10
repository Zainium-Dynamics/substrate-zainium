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

        #[arg(long, default_value_t = false)]
        report: bool,

        /// Union-layer root used to render install paths when
        /// auto-generating a manifest.toml (only matters when `directory`
        /// has no manifest.toml of its own — a real one ignores this).
        #[arg(long, default_value = "/overlayer/zexlib")]
        install_root: String,

        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },

    /// Extract a .zex package
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
