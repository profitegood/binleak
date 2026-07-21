use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::config::Config;
use crate::reporter::{OutputFormat, Reporter};
use crate::scanner::Scanner;

#[derive(Parser)]
#[command(name = "binleak", about = "Static secret scanner for compiled binaries", version, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a binary file, directory, or Docker image for secrets
    Scan {
        /// Path to binary file or directory (use --docker for image references)
        path: String,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: CliFormat,

        /// Write output to file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verify discovered keys against live APIs
        #[arg(long)]
        verify: bool,

        /// Minimum severity level to report
        #[arg(long, value_enum, default_value = "low")]
        min_severity: CliSeverity,

        /// Minimum Shannon entropy threshold
        #[arg(long, default_value = "3.5")]
        min_entropy: f64,

        /// Treat PATH as a Docker image reference
        #[arg(long)]
        docker: bool,

        /// Skip XOR brute-force extraction (faster scan)
        #[arg(long)]
        no_xor: bool,

        /// Path to custom rules YAML file
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Glob patterns to exclude (repeatable)
        #[arg(long)]
        exclude: Vec<String>,

        /// Only print findings, no progress output
        #[arg(short, long)]
        quiet: bool,

        /// Path to config file [default: .binleak.toml]
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Print all built-in detection rules
    Rules,
}

#[derive(ValueEnum, Clone)]
pub enum CliFormat {
    Text,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, PartialEq, PartialOrd)]
pub enum CliSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Commands::Scan {
                path, format, output, verify, min_severity, min_entropy,
                docker, no_xor, rules, exclude, quiet, config,
            } => {
                let cfg = Config::load(config)?;

                let output_format = match format {
                    CliFormat::Text => OutputFormat::Text,
                    CliFormat::Json => OutputFormat::Json,
                    CliFormat::Sarif => OutputFormat::Sarif,
                };

                let severity_threshold = match min_severity {
                    CliSeverity::Low => crate::detector::Severity::Low,
                    CliSeverity::Medium => crate::detector::Severity::Medium,
                    CliSeverity::High => crate::detector::Severity::High,
                    CliSeverity::Critical => crate::detector::Severity::Critical,
                };

                let scanner = Scanner::new(
                    cfg, verify, severity_threshold, min_entropy,
                    !no_xor, rules, exclude, quiet,
                );

                let results = if docker {
                    scanner.scan_docker(&path)?
                } else {
                    scanner.scan_path(&path)?
                };

                let reporter = Reporter::new(output_format, output);
                reporter.report(&results)?;

                if !results.findings.is_empty() {
                    std::process::exit(1);
                }

                Ok(())
            }

            Commands::Rules => {
                let rules = crate::detector::rules::builtin_rules();
                println!("{:<30} {:<10} {}", "Rule ID", "Severity", "Description");
                println!("{}", "─".repeat(80));
                for rule in rules {
                    println!("{:<30} {:<10} {}", rule.id, rule.severity.as_str(), rule.description);
                }
                Ok(())
            }
        }
    }
}
