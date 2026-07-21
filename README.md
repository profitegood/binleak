# BinLeak
 
Static secret scanner for compiled binaries.
 
[![Crates.io](https://img.shields.io/crates/v/binleak)](https://crates.io/crates/binleak)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/profitegood/binleak/actions/workflows/ci.yml/badge.svg)](https://github.com/profitegood/binleak/actions)
 
Most secret scanners — TruffleHog, Gitleaks, trufflehog — only look at source code and git history. BinLeak looks inside the compiled output: ELF, PE, Mach-O, and WebAssembly files. That is where secrets actually end up in production when a developer hardcodes a credential and ships the binary.
 
---
 
## Table of Contents
 
- [How It Works](#how-it-works)
- [Supported Formats](#supported-formats)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Detection Methods](#detection-methods)
- [Verification](#verification)
- [CI/CD Integration](#cicd-integration)
- [Configuration](#configuration)
- [Custom Rules](#custom-rules)
- [Built-in Rules](#built-in-rules)
- [Roadmap](#roadmap)
---
 
## How It Works
 
BinLeak runs four extraction passes over every section of the binary, then scores each string by Shannon entropy, then matches high-entropy strings against a library of 50+ regex rules.
 
```
binary file
    |
    v
parser  —  reads section headers (ELF / PE / Mach-O / Wasm)
    |
    v
extractor  —  pulls strings in 4 encodings: ASCII, UTF-16, Base64, XOR-decoded
    |
    v
entropy filter  —  drops strings below the configured threshold (default 3.5)
    |
    v
rule engine  —  matches against 50+ patterns (AWS, GitHub, JWT, SSH, Stripe ...)
    |
    v
verifier (optional)  —  makes a real API call to confirm the credential is live
    |
    v
reporter  —  outputs text, JSON, or SARIF
```
 
**ASCII extraction** finds contiguous printable byte sequences, the same as the Unix `strings` utility but with a configurable minimum length.
 
**UTF-16 extraction** covers Windows PE binaries, which store string literals in UTF-16LE.
 
**Base64 extraction** detects base64-encoded blobs, decodes them, and scans the decoded content. Credentials are sometimes stored encoded rather than in plain text.
 
**XOR extraction** brute-forces all 255 single-byte XOR keys. If the decoded output is more than 85% printable ASCII and has entropy above 3.2, it is treated as an obfuscated string and passed to the rule engine.
 
**Shannon entropy** measures how random a string looks. Readable English scores around 2.5 to 3.5. A 20-character API key scores 4.5 to 5.5. Strings below the threshold are discarded before pattern matching, which eliminates most false positives.
 
---
 
## Supported Formats
 
| Format | Extensions | Platform |
|--------|-----------|----------|
| ELF | no extension, `.elf` | Linux, Android |
| PE | `.exe`, `.dll` | Windows |
| Mach-O | no extension, `.dylib` | macOS, iOS |
| WebAssembly | `.wasm` | Browser, WASI |
| Raw | any | fallback |
 
---
 
## Installation
 
**From crates.io:**
 
```
cargo install binleak
```
 
**From source:**
 
```
git clone https://github.com/profitegood/binleak
cd binleak
cargo build --release
./target/release/binleak --version
```
 
Pre-built binaries for Linux x86_64, Windows x86_64, and macOS arm64 are available on the [Releases](https://github.com/profitegood/binleak/releases) page.
 
---
 
## Usage
 
**Scan a single binary:**
 
```
binleak scan ./target/release/myapp
```
 
**Scan a directory recursively:**
 
```
binleak scan ./dist/
```
 
**Scan a Docker image:**
 
```
binleak scan --docker nginx:latest
```
 
**Scan and verify findings against live APIs:**
 
```
binleak scan ./myapp --verify
```
 
**Output as JSON:**
 
```
binleak scan ./myapp --format json
```
 
**Output as SARIF for GitHub Code Scanning:**
 
```
binleak scan ./myapp --format sarif -o results.sarif
```
 
**Only report high severity and above:**
 
```
binleak scan ./myapp --min-severity high
```
 
**Skip XOR brute-force for faster scans:**
 
```
binleak scan ./myapp --no-xor
```
 
**Use a custom rules file:**
 
```
binleak scan ./myapp --rules ./rules/company.yml
```
 
**Full options:**
 
```
USAGE:
    binleak scan [OPTIONS] <PATH>
 
ARGS:
    <PATH>    Path to binary file, directory, or Docker image reference
 
OPTIONS:
    -f, --format <FORMAT>            Output format: text, json, sarif [default: text]
    -o, --output <FILE>              Write output to file instead of stdout
        --verify                     Verify keys against live APIs
        --min-severity <LEVEL>       Minimum severity: low, medium, high, critical [default: low]
        --min-entropy <FLOAT>        Minimum Shannon entropy [default: 3.5]
        --docker                     Treat PATH as a Docker image reference
        --no-xor                     Skip XOR brute-force extraction
        --rules <FILE>               Path to custom rules YAML file
        --exclude <PATTERN>          Glob pattern to exclude files (repeatable)
    -q, --quiet                      Only print findings, suppress progress output
        --config <FILE>              Path to config file [default: .binleak.toml]
    -h, --help                       Print help
    -V, --version                    Print version
```
 
**List all built-in rules:**
 
```
binleak rules
```
 
---
 
## Output
 
**Text output — no findings:**
 
```
binleak 0.1.0
-> ./target/release/myapp . ELF . x86_64
 
No secrets found
 
  Scanned 1 file(s) in 180ms
```
 
**Text output — findings:**
 
```
binleak 0.1.0
-> ./target/release/myapp . ELF . x86_64
 
[CRITICAL] AWS Access Key ID
  Rule:      aws_access_key_id
  Offset:    0x004a3f20
  Section:   .rodata
  Encoding:  ascii
  Entropy:   4.82
  Value:     AKIA••••••••••••MPLE
 
[CRITICAL] PostgreSQL Connection String
  Rule:      postgres_connection_string
  Offset:    0x004a4100
  Section:   .rodata
  Encoding:  ascii
  Entropy:   4.21
  Value:     post••••••••••••••••••5432
 
[HIGH] JSON Web Token
  Rule:      jwt_token
  Offset:    0x004b2240
  Section:   .data
  Encoding:  base64
  Entropy:   5.10
  Value:     eyJh••••••••••••••••••••••••••••••••••••pXV
 
3 finding(s)  critical:2  high:1  medium:0  low:0
  Scanned 1 file(s) in 312ms
```
 
**With --verify:**
 
```
[CRITICAL] AWS Access Key ID
  Rule:      aws_access_key_id
  Offset:    0x004a3f20
  Section:   .rodata
  Encoding:  ascii
  Entropy:   4.82
  Value:     AKIA••••••••••••MPLE
  Status:    LIVE
```
 
**JSON output:**
 
```json
{
  "scan": {
    "target": "./myapp",
    "binary_format": "ELF64",
    "arch": "x86_64",
    "files_scanned": 1,
    "duration_ms": 312,
    "total_findings": 1
  },
  "findings": [
    {
      "rule_id": "aws_access_key_id",
      "description": "AWS Access Key ID",
      "severity": "critical",
      "redacted_value": "AKIA••••••••••••MPLE",
      "offset": 4866848,
      "section": ".rodata",
      "encoding": "ascii",
      "entropy": 4.82,
      "verification": "live"
    }
  ]
}
```
 
---
 
## Detection Methods
 
**String extraction** runs four passes per section:
 
- ASCII: contiguous printable bytes, minimum length 6
- UTF-16LE / UTF-16BE: two-byte encoded characters, common in Windows binaries
- Base64: detects and decodes base64 blobs before scanning
- XOR: brute-forces all 255 single-byte keys, keeps results with entropy above 3.2
**Entropy scoring** uses the Shannon formula to measure randomness. API keys and tokens have high entropy. Natural language and code identifiers have low entropy. Strings below the configured threshold are dropped before pattern matching.
 
**Rule matching** applies regex patterns to the remaining strings. Each rule has an ID, a severity level, and a regex. The highest-priority matching rule wins per string. Custom rules can be added via a YAML file.
 
---
 
## Verification
 
When `--verify` is passed, BinLeak makes a real HTTP request to confirm whether each credential is still active.
 
| Provider | Method | Live indicator |
|----------|--------|---------------|
| AWS | STS GetCallerIdentity | AuthFailure response (key exists, no secret) |
| GitHub | GET /user | HTTP 200 |
| Stripe | GET /v1/account | HTTP 200 |
| OpenAI | GET /v1/models | HTTP 200 |
 
Verification results:
 
- `LIVE` — credential was accepted or confirmed to exist by the provider
- `REVOKED` — credential was rejected by the provider
- `UNKNOWN` — network error or unsupported provider
- `UNVERIFIED` — `--verify` was not passed
Only use `--verify` on binaries you own or have authorization to test. Making API calls with a found credential against a third-party system without permission may be unauthorized access.
 
---
 
## CI/CD Integration
 
**GitHub Actions:**
 
```yaml
name: Secret Scan
 
on: [push, pull_request]
 
jobs:
  binleak:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
 
      - name: Build
        run: cargo build --release
 
      - name: Install binleak
        run: cargo install binleak
 
      - name: Scan
        run: |
          binleak scan ./target/release/myapp \
            --format sarif \
            --min-severity high \
            -o binleak.sarif
 
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: binleak.sarif
```
 
Findings appear in the Security tab of the repository under Code Scanning alerts.
 
**GitLab CI:**
 
```yaml
binleak:
  stage: test
  script:
    - cargo install binleak
    - binleak scan ./target/release/myapp --format json -o binleak.json
  artifacts:
    paths:
      - binleak.json
    when: always
```
 
---
 
## Configuration
 
BinLeak reads `.binleak.toml` from the current directory, or from a path passed with `--config`.
 
```toml
[scan]
min_entropy = 3.5
verify = false
 
[extraction]
min_string_length = 6
xor_bruteforce = true
decode_base64 = true
 
[output]
redact = true
```
 
Command-line flags override config file values.
 
---
 
## Custom Rules
 
Add your own patterns in a YAML file and pass it with `--rules`:
 
```yaml
rules:
  - id: company_internal_token
    description: "Company internal service token"
    severity: critical
    pattern: "INT-[A-Z0-9]{32}"
 
  - id: internal_db_dsn
    description: "Internal database connection string"
    severity: high
    pattern: "postgresql://[^:]+:[^@]+@internal\\.company\\.com"
```
 
Severity values: `critical`, `high`, `medium`, `low`.
 
---
 
## Built-in Rules
 
```
Rule ID                        Severity   Description
--------------------------------------------------------------------------------
aws_access_key_id              critical   AWS Access Key ID
aws_secret_access_key          critical   AWS Secret Access Key
github_pat_classic             critical   GitHub Personal Access Token (classic)
github_pat_fine                critical   GitHub Fine-Grained PAT
openai_api_key                 critical   OpenAI API Key
anthropic_api_key              critical   Anthropic API Key
stripe_secret_key              critical   Stripe Secret Key
sendgrid_api_key               critical   SendGrid API Key
slack_bot_token                critical   Slack Bot Token
ssh_private_key                critical   SSH Private Key
pem_private_key                critical   PEM Private Key
pgp_private_key                critical   PGP Private Key
postgres_connection_string     critical   PostgreSQL Connection String
mysql_connection_string        critical   MySQL Connection String
mongodb_connection_string      critical   MongoDB Connection String
jwt_secret                     critical   JWT Secret / Signing Key
ethereum_private_key           critical   Ethereum Private Key
bitcoin_private_key_wif        critical   Bitcoin Private Key (WIF)
npm_access_token               critical   npm Access Token
pypi_api_token                 critical   PyPI API Token
discord_bot_token              critical   Discord Bot Token
google_api_key                 high       Google API Key
jwt_token                      high       JSON Web Token
slack_webhook                  high       Slack Webhook URL
twilio_api_key                 high       Twilio API Key
mailgun_api_key                high       Mailgun API Key
bearer_token                   high       Bearer token in string
redis_url_with_password        high       Redis URL with Password
discord_webhook                high       Discord Webhook URL
telegram_bot_token             high       Telegram Bot Token
generic_password               medium     Generic password in config
generic_secret                 medium     Generic secret in config
generic_api_key                medium     Generic API key
stripe_publishable_key         low        Stripe Publishable Key
```
 
---
 
## Roadmap
 
- YARA rule support
- Multi-byte XOR key brute-force
- UPX/packed binary detection
- Additional verifiers: Twilio, SendGrid, Slack, OpenAI
- CycloneDX SBOM output
- Android APK support
- VS Code extension
---
 
## License
 
MIT
 
