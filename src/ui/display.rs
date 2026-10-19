// Terminal output formatting utilities.


const G:   &str = "\x1b[92m";
const P:   &str = "\x1b[95m";
const B:   &str = "\x1b[96m";
const Y:   &str = "\x1b[93m";
const R:   &str = "\x1b[91m";
const DIM: &str = "\x1b[2m";
const BLD: &str = "\x1b[1m";
const RST: &str = "\x1b[0m";


pub fn title(msg: &str) {
    println!("\n {BLD}{G}substrate{RST} {G}— {msg}{RST}");
}

pub fn step(msg: &str) {
    println!("\n {G}→{RST} {msg}");
}

pub fn kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {B}{value}{RST}");
}

pub fn ok_kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {G}✓{RST}  {value}");
}

pub fn fail_kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {R}✗{RST}  {value}");
}

pub fn warn_kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {Y}⚠{RST}  {value}");
}

pub fn success(msg: &str) {
    println!("\n {G}✓ {BLD}{msg}{RST}\n");
}

pub fn error(msg: &str) {
    eprintln!("\n {R}✗ Error:{RST} {msg}\n");
}

pub fn section(msg: &str) {
    println!("\n{G}{msg}{RST}");
}

pub fn help() {
    println!();
    println!("  {BLD}{B}substrate{RST} — {BLD}Zainium Package Builder & Verifier{RST}");
    println!();
    println!("  {BLD}Usage:{RST}  substrate <command> [options]");
    println!();
    println!("  {Y}Packages:{RST}");
    println!("    {G}pack{RST}    {DIM}<dir> -v <ver>{RST}  Build a signed .zex from <dir> {DIM}(manifest.toml + payload/){RST}");
    println!("    {G}unpack{RST}  {DIM}<file.zex>{RST}      Verify and extract a package {DIM}(-o <dir>){RST}");
    println!("    {G}verify{RST}  {DIM}<file.zex>{RST}      Check signature and integrity");
    println!("    {G}inspect{RST} {DIM}<file.zex>{RST}      Show package information");
    println!();
    println!("  {Y}Keys:{RST}");
    println!("    {G}keygen{RST}                  Generate an Ed25519 signing key {DIM}(-o <file>, --force){RST}");
    println!();
    println!("  {Y}Pack Options:{RST}");
    println!("    {G}-v, --version{RST} {DIM}<ver>{RST}     Package version {DIM}(required){RST}");
    println!("    {G}-o, --output{RST} {DIM}<file>{RST}     Output file {DIM}(default: <dir>-<ver>.zex){RST}");
    println!("    {G}--description{RST} {DIM}<text>{RST}    Package description");
    println!("    {G}--features{RST} {DIM}<a,b>{RST}        Comma-separated features");
    println!("    {G}--requires-syshub{RST} {DIM}<ver>{RST} Syshub release the package needs");
    println!("    {G}--install-root{RST} {DIM}<path>{RST}   Root for a generated manifest {DIM}(default: /overlayer/zexlib){RST}");
    println!();
    println!("  Run {G}substrate <command> --help{RST} for a command's own options.");
    println!();
    println!("  Zainium OS — {B}archive.zainiumdynamics.tech{RST}");
    println!();
}
