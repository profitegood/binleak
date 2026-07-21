pub mod json;
pub mod sarif;
pub mod text;

use anyhow::Result;
use std::path::PathBuf;

use crate::scanner::ScanResults;

#[derive(Clone)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

pub struct Reporter {
    format: OutputFormat,
    output: Option<PathBuf>,
}

impl Reporter {
    pub fn new(format: OutputFormat, output: Option<PathBuf>) -> Self {
        Self { format, output }
    }

    pub fn report(&self, results: &ScanResults) -> Result<()> {
        let content = match self.format {
            OutputFormat::Text => text::render(results),
            OutputFormat::Json => json::render(results)?,
            OutputFormat::Sarif => sarif::render(results)?,
        };

        match &self.output {
            Some(path) => std::fs::write(path, content)?,
            None => print!("{}", content),
        }

        Ok(())
    }
}
