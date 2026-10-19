//! `rescue`: the five restore steps on the command line. This skeleton only
//! answers `--version`; the steps arrive with the core modules they drive.

use clap::Parser;

/// Winnow Rescue: sweep coins out of any old wallet into a taproot account.
#[derive(Parser)]
#[command(name = "rescue", version = rescue_core::VERSION)]
struct Cli {}

fn main() {
    let Cli {} = Cli::parse();
    println!("rescue {}", rescue_core::VERSION);
}
