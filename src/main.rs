mod cli;
mod config;
mod detector;
mod extractor;
mod parser;
mod reporter;
mod scanner;
mod verifier;

use anyhow::Result;
use cli::Cli;
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run()
}
