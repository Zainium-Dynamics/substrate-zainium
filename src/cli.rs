use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "substrate", about = "Zainium Package Builder and Verifier")]
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

        /// Target syshub release version.
        #[arg(long)]
        requires_syshub: Option<String>,

        /// Installation root path for auto-generated manifests.

        #[arg(long, default_value = "/overlayer/zexlib")]
        install_root: String,

        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },

    /// Extract a .zex package.
    Unpack {
        file: PathBuf,

        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        verify_only: bool,
    },

    /// Verify signature and integrity of a .zex package.
    Verify { file: PathBuf },

    /// Show detailed package information.
    Inspect { file: PathBuf },

    /// Generate an Ed25519 keypair.
    Keygen {
        /// Secret key output destination.
        #[arg(short = 'o', long = "output", default_value = "signing.key")]
        output: PathBuf,

        /// Overwrite destination file if it exists.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

