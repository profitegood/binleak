use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::config::Config;
use crate::detector::{Detector, Finding, Severity};
use crate::extractor::{self, ExtractorConfig};
use crate::parser;
use crate::verifier;

pub struct ScanResults {
    pub target: String,
    pub format: String,
    pub arch: String,
    pub findings: Vec<Finding>,
    pub duration_ms: u128,
    pub files_scanned: usize,
}

pub struct Scanner {
    config: Config,
    verify: bool,
    min_severity: Severity,
    min_entropy: f64,
    xor: bool,
    custom_rules_path: Option<PathBuf>,
    exclude: Vec<String>,
    quiet: bool,
}

impl Scanner {
    pub fn new(
        config: Config,
        verify: bool,
        min_severity: Severity,
        min_entropy: f64,
        xor: bool,
        custom_rules_path: Option<PathBuf>,
        exclude: Vec<String>,
        quiet: bool,
    ) -> Self {
        Self { config, verify, min_severity, min_entropy, xor, custom_rules_path, exclude, quiet }
    }

    pub fn scan_path(&self, path: &str) -> Result<ScanResults> {
        let p = Path::new(path);
        if p.is_dir() {
            self.scan_directory(p, path)
        } else {
            self.scan_file(p, path)
        }
    }

    fn scan_file(&self, path: &Path, label: &str) -> Result<ScanResults> {
        let start = Instant::now();

        let pb = if !self.quiet {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template("{spinner:.cyan} {msg}")
                    .unwrap()
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
            );
            pb.set_message(format!("Scanning {}", path.display()));
            pb.enable_steady_tick(std::time::Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };

        let parsed = parser::parse(path)?;
        let format = parsed.format.as_str().to_string();
        let arch = parsed.arch.clone();

        let ext_cfg = ExtractorConfig {
            min_length: self.config.extraction.min_string_length,
            xor_bruteforce: self.xor && self.config.extraction.xor_bruteforce,
            decode_base64: self.config.extraction.decode_base64,
            min_entropy: self.min_entropy,
        };

        let strings = extractor::extract_all(&parsed.sections, &ext_cfg);

        let custom_rules = if let Some(ref rules_path) = self.custom_rules_path {
            load_custom_rules(rules_path)?
        } else {
            vec![]
        };

        let detector = Detector::new(custom_rules, self.min_entropy, self.min_severity.clone());
        let mut findings = detector.detect(&strings);

        if self.verify {
            verifier::verify_findings(&mut findings);
        }

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }

        Ok(ScanResults {
            target: label.to_string(),
            format,
            arch,
            findings,
            duration_ms: start.elapsed().as_millis(),
            files_scanned: 1,
        })
    }

    fn scan_directory(&self, dir: &Path, label: &str) -> Result<ScanResults> {
        let start = Instant::now();

        let files: Vec<PathBuf> = walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| !self.is_excluded(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        let pb = if !self.quiet {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} {msg}",
                )
                .unwrap()
                .progress_chars("█▓░"),
            );
            Some(pb)
        } else {
            None
        };

        let mut all_findings = Vec::new();
        let mut files_scanned = 0;

        let detector = Detector::new(vec![], self.min_entropy, self.min_severity.clone());
        let ext_cfg = ExtractorConfig {
            min_length: self.config.extraction.min_string_length,
            xor_bruteforce: self.xor,
            decode_base64: self.config.extraction.decode_base64,
            min_entropy: self.min_entropy,
        };

        for file in &files {
            if let Some(pb) = &pb {
                pb.set_message(file.file_name().unwrap_or_default().to_string_lossy().to_string());
            }

            if let Ok(parsed) = parser::parse(file) {
                let strings = extractor::extract_all(&parsed.sections, &ext_cfg);
                let mut findings = detector.detect(&strings);

                for f in &mut findings {
                    f.section = format!("{}::{}", file.display(), f.section);
                }

                all_findings.extend(findings);
                files_scanned += 1;
            }

            if let Some(pb) = &pb {
                pb.inc(1);
            }
        }

        if self.verify {
            verifier::verify_findings(&mut all_findings);
        }

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }

        Ok(ScanResults {
            target: label.to_string(),
            format: "directory".to_string(),
            arch: "mixed".to_string(),
            findings: all_findings,
            duration_ms: start.elapsed().as_millis(),
            files_scanned,
        })
    }

    pub fn scan_docker(&self, image: &str) -> Result<ScanResults> {
        let tmp = tempfile::tempdir()?;
        let tmp_path = tmp.path();

        let save_status = std::process::Command::new("docker")
            .args(["save", image, "-o"])
            .arg(tmp_path.join("image.tar"))
            .status()
            .map_err(|_| anyhow::anyhow!("docker not found in PATH"))?;

        if !save_status.success() {
            anyhow::bail!(
                "Failed to save Docker image '{}'. Is Docker running and is the image available?",
                image
            );
        }

        let extract_dir = tmp_path.join("layers");
        std::fs::create_dir_all(&extract_dir)?;
        std::process::Command::new("tar")
            .args(["-xf"])
            .arg(tmp_path.join("image.tar"))
            .args(["-C"])
            .arg(&extract_dir)
            .status()?;

        let layer_tars: Vec<_> = walkdir::WalkDir::new(&extract_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() == "layer.tar")
            .map(|e| e.path().to_path_buf())
            .collect();

        for layer_tar in &layer_tars {
            let layer_out = layer_tar.parent().unwrap().join("extracted");
            std::fs::create_dir_all(&layer_out)?;
            let _ = std::process::Command::new("tar")
                .args(["-xf"])
                .arg(layer_tar)
                .args(["-C"])
                .arg(&layer_out)
                .status();
        }

        let mut result = self.scan_directory(&extract_dir, image)?;
        result.format = "docker".to_string();
        result.target = image.to_string();
        drop(tmp);
        Ok(result)
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.exclude.iter().any(|pattern| {
            glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
        })
    }
}

fn load_custom_rules(path: &Path) -> Result<Vec<crate::detector::rules::Rule>> {
    use regex::Regex;

    #[derive(serde::Deserialize)]
    struct RuleFile {
        rules: Vec<RuleEntry>,
    }

    #[derive(serde::Deserialize)]
    struct RuleEntry {
        id: String,
        description: String,
        severity: String,
        pattern: String,
    }

    let content = std::fs::read_to_string(path)?;
    let file: RuleFile = serde_yaml::from_str(&content)?;

    let mut rules = Vec::new();
    for entry in file.rules {
        let severity = match entry.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        };

        match Regex::new(&entry.pattern) {
            Ok(regex) => rules.push(crate::detector::rules::Rule {
                id: entry.id,
                description: entry.description,
                severity,
                regex,
                verifier: None,
            }),
            Err(e) => eprintln!("Warning: invalid regex in custom rule '{}': {}", entry.id, e),
        }
    }

    Ok(rules)
}
