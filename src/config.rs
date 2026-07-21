use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub extraction: ExtractionConfig,

    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Deserialize)]
pub struct ScanConfig {
    pub min_entropy: f64,
    pub verify: bool,
}

#[derive(Debug, Deserialize)]
pub struct ExtractionConfig {
    pub min_string_length: usize,
    pub xor_bruteforce: bool,
    pub decode_base64: bool,
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    pub redact: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { min_entropy: 3.5, verify: false }
    }
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self { min_string_length: 6, xor_bruteforce: true, decode_base64: true }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self { redact: true }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let config_path = path
            .or_else(|| {
                let local = PathBuf::from(".binleak.toml");
                if local.exists() { Some(local) } else { None }
            });

        match config_path {
            Some(p) => {
                let content = std::fs::read_to_string(p)?;
                Ok(toml::from_str(&content)?)
            }
            None => Ok(Config::default()),
        }
    }
}
