#![allow(dead_code)]
// Substrate package builder for .zex packages.

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
    // Rust ignores SIGPIPE, so printing into a closed pipe (`substrate --help | head`)
    // panicked; with the default action the process ends quietly, like any C tool.
    #[cfg(unix)]
    // SAFETY: called once at start-up, before any other thread exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    run(args);
}

