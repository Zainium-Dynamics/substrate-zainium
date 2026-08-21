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
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    run(args);
}

