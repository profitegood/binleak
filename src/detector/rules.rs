use once_cell::sync::Lazy;
use regex::Regex;
use super::Severity;

pub struct Rule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub regex: Regex,
    pub verifier: Option<String>,
}

macro_rules! rule {
    ($id:expr, $desc:expr, $sev:expr, $pattern:expr) => {
        Rule {
            id: $id.to_string(),
            description: $desc.to_string(),
            severity: $sev,
            regex: Regex::new($pattern).expect(concat!("Invalid regex for rule: ", $id)),
            verifier: None,
        }
    };
    ($id:expr, $desc:expr, $sev:expr, $pattern:expr, $verifier:expr) => {
        Rule {
            id: $id.to_string(),
            description: $desc.to_string(),
            severity: $sev,
            regex: Regex::new($pattern).expect(concat!("Invalid regex for rule: ", $id)),
            verifier: Some($verifier.to_string()),
        }
    };
}

pub fn builtin_rules() -> Vec<Rule> {
    vec![
        rule!("aws_access_key_id", "AWS Access Key ID", Severity::Critical,
            r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)", "aws"),
        rule!("aws_secret_access_key", "AWS Secret Access Key", Severity::Critical,
            r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*([A-Za-z0-9/+]{40})", "aws"),
        rule!("aws_session_token", "AWS Session Token", Severity::Critical,
            r"(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*([A-Za-z0-9/+=]{100,})"),

        rule!("github_pat_classic", "GitHub Personal Access Token (classic)", Severity::Critical,
            r"ghp_[A-Za-z0-9]{36}", "github"),
        rule!("github_pat_fine", "GitHub Fine-Grained PAT", Severity::Critical,
            r"github_pat_[A-Za-z0-9_]{82}", "github"),
        rule!("github_oauth", "GitHub OAuth Token", Severity::Critical,
            r"gho_[A-Za-z0-9]{36}"),
        rule!("github_app_token", "GitHub App Installation Token", Severity::Critical,
            r"ghs_[A-Za-z0-9]{36}"),

        rule!("google_api_key", "Google API Key", Severity::High,
            r"AIza[0-9A-Za-z\-_]{35}"),
        rule!("google_oauth_client_secret", "Google OAuth Client Secret", Severity::Critical,
            r"GOCSPX-[A-Za-z0-9\-_]{28}"),
        rule!("google_service_account", "Google Service Account Key", Severity::Critical,
            r#""type"\s*:\s*"service_account""#),

        rule!("stripe_secret_key", "Stripe Secret Key", Severity::Critical,
            r"sk_live_[0-9a-zA-Z]{24}", "stripe"),
        rule!("stripe_restricted_key", "Stripe Restricted Key", Severity::Critical,
            r"rk_live_[0-9a-zA-Z]{24}"),
        rule!("stripe_publishable_key", "Stripe Publishable Key (lower risk)", Severity::Low,
            r"pk_live_[0-9a-zA-Z]{24}"),

        rule!("openai_api_key", "OpenAI API Key", Severity::Critical,
            r"sk-[A-Za-z0-9]{48}", "openai"),
        rule!("openai_project_key", "OpenAI Project API Key", Severity::Critical,
            r"sk-proj-[A-Za-z0-9\-_]{48,}"),

        rule!("anthropic_api_key", "Anthropic API Key", Severity::Critical,
            r"sk-ant-[A-Za-z0-9\-_]{95,}"),

        rule!("slack_bot_token", "Slack Bot Token", Severity::Critical,
            r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}"),
        rule!("slack_user_token", "Slack User Token", Severity::Critical,
            r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}"),
        rule!("slack_webhook", "Slack Webhook URL", Severity::High,
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),

        rule!("twilio_api_key", "Twilio API Key", Severity::High,
            r"SK[0-9a-fA-F]{32}"),
        rule!("twilio_auth_token", "Twilio Auth Token", Severity::Critical,
            r"(?:twilio|TWILIO).*['\"][0-9a-fA-F]{32}['\"]"),

        rule!("sendgrid_api_key", "SendGrid API Key", Severity::Critical,
            r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),

        rule!("mailgun_api_key", "Mailgun API Key", Severity::High,
            r"key-[0-9a-zA-Z]{32}"),

        rule!("cloudflare_api_token", "Cloudflare API Token", Severity::Critical,
            r"[A-Za-z0-9_\-]{40}(?=.*cloudflare|.*CF_)"),
        rule!("cloudflare_global_api_key", "Cloudflare Global API Key", Severity::Critical,
            r"(?:cloudflare|CLOUDFLARE).*['\"][A-Za-z0-9]{37}['\"]"),

        rule!("azure_subscription_key", "Azure Subscription Key", Severity::High,
            r"[Ss]ubscription[_-]?[Kk]ey.*['\"][A-Za-z0-9]{32}['\"]"),
        rule!("azure_client_secret", "Azure Client Secret", Severity::Critical,
            r"[A-Za-z0-9~]{34}~[A-Za-z0-9~]{3}~[A-Za-z0-9~]{8}"),

        rule!("jwt_token", "JSON Web Token", Severity::High,
            r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        rule!("jwt_secret", "JWT Secret / Signing Key", Severity::Critical,
            r"(?:jwt[_\-]?secret|JWT[_\-]?SECRET|jwt[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+_\-]{16,})['\"]?"),

        rule!("ssh_private_key", "SSH Private Key", Severity::Critical,
            r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
        rule!("pem_private_key", "PEM Private Key", Severity::Critical,
            r"-----BEGIN PRIVATE KEY-----"),
        rule!("pgp_private_key", "PGP Private Key", Severity::Critical,
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),

        rule!("postgres_connection_string", "PostgreSQL Connection String", Severity::Critical,
            r"postgresql://[^:]+:[^@]+@[^/]+/[A-Za-z0-9_]+"),
        rule!("mysql_connection_string", "MySQL Connection String", Severity::Critical,
            r"mysql://[^:]+:[^@]+@[^/]+/[A-Za-z0-9_]+"),
        rule!("mongodb_connection_string", "MongoDB Connection String", Severity::Critical,
            r"mongodb(\+srv)?://[^:]+:[^@]+@[A-Za-z0-9._\-]+"),
        rule!("redis_url_with_password", "Redis URL with Password", Severity::High,
            r"redis://:[^@]+@[A-Za-z0-9._\-]+"),

        rule!("generic_password", "Generic password in config", Severity::Medium,
            r#"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'"]{8,})['\"]"#),
        rule!("generic_secret", "Generic secret in config", Severity::Medium,
            r#"(?:secret|SECRET)\s*[=:]\s*['\"]([A-Za-z0-9/+_\-]{16,})['\"]"#),
        rule!("generic_api_key", "Generic API key", Severity::Medium,
            r#"(?:api[_\-]?key|API[_\-]?KEY)\s*[=:]\s*['\"]([A-Za-z0-9/+_\-]{16,})['\"]"#),
        rule!("bearer_token", "Bearer token in string", Severity::High,
            r"Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)"),

        rule!("ethereum_private_key", "Ethereum Private Key", Severity::Critical,
            r"(?:^|[^A-Fa-f0-9])(0x[A-Fa-f0-9]{64})(?:[^A-Fa-f0-9]|$)"),
        rule!("bitcoin_private_key_wif", "Bitcoin Private Key (WIF)", Severity::Critical,
            r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}"),

        rule!("discord_bot_token", "Discord Bot Token", Severity::Critical,
            r"[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}"),
        rule!("discord_webhook", "Discord Webhook URL", Severity::High,
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
        rule!("telegram_bot_token", "Telegram Bot Token", Severity::High,
            r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"),
        rule!("npm_access_token", "npm Access Token", Severity::Critical,
            r"npm_[A-Za-z0-9]{36}"),
        rule!("pypi_api_token", "PyPI API Token", Severity::Critical,
            r"pypi-[A-Za-z0-9\-_]{80,}"),
    ]
}
