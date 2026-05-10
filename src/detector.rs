//! Credential pattern detectors and the engine that drives them.
//!
//! Each [`Detector`] is a regex with metadata. The engine walks an input
//! string line-by-line and yields a [`Finding`] for every match. The two
//! detector flavours are:
//!
//! 1. **Vendor-specific** patterns — Anthropic `sk-ant-…`, OpenAI `sk-…`,
//!    AWS `AKIA…`, GitHub `gh[opsu]_…`, Slack `xox[abprs]-…`, etc. These
//!    are high-precision: a match is almost certainly a real key.
//! 2. **Generic high-entropy** — long base64-ish strings near keywords
//!    like `key`, `token`, `secret`. Lower precision; useful as a
//!    backstop for vendors we don't have explicit detectors for.
//!
//! ## Output safety
//!
//! Findings hold the **raw** secret in [`Finding::raw_match`] (so callers
//! that need to verify the hit can do so), but every formatter MUST go
//! through redacted forms for human consumption. The CLI redacts by
//! default; `--unredacted` flips it back at the user's explicit request,
//! with a banner reminding them they're producing a secrets file.
//!
//! Generic-detector entropy floor is 4.0 bits/byte: random base64 lands
//! 4.5–5.5, English prose ~4.0, so 4.0 + a length floor keeps short
//! identifiers from tripping the catch-all rule.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Almost certainly a live credential — high-precision vendor match.
    Critical,
    /// Probable credential — vendor pattern with weaker anchors.
    High,
    /// Possible credential — generic high-entropy near a sensitive keyword.
    Medium,
    /// Suspicious; surfaced for review.
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
    pub fn from_min(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub detector: String,
    pub severity: Severity,
    /// Where the match came from. Source-specific: a path for local-fs,
    /// `owner/repo:path@ref` for GitHub, `slack://channel/ts` for Slack.
    pub location: String,
    pub line: u32,
    /// The exact substring that matched. **Treat as a secret.** Formatters
    /// must redact unless the user explicitly opts in.
    pub raw_match: String,
    /// ±2 lines of source context, with the secret already redacted in
    /// place. Safe to display.
    pub context: Option<String>,
}

impl Finding {
    /// Stable hash of the raw secret for dedup. SHA-256 truncated to 16
    /// hex chars — collision-resistant enough for reporting; cheap to
    /// compare.
    pub fn fingerprint(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(self.raw_match.as_bytes());
        let digest = hasher.finalize();
        hex::encode(&digest[..8])
    }

    /// Return `<first 4>…<last 4>` for any token longer than 12 chars,
    /// otherwise `<redacted>`. The "show edges" pattern lets reviewers
    /// recognise a key they've seen elsewhere without exposing the
    /// middle.
    pub fn redacted(&self) -> String {
        redact(&self.raw_match)
    }
}

pub fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 12 {
        return "<redacted>".to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{}…{}", head, tail)
}

#[derive(Debug, Clone)]
pub struct Detector {
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    /// Regex over a single line of source. If a capture group is
    /// present, group 1 is the secret; otherwise the whole match is.
    pub pattern: Regex,
    /// Optional Shannon-entropy floor (bits/byte). When set, the
    /// matched secret must clear this to fire. Used by the generic
    /// detector to suppress identifiers that look pattern-shaped but
    /// are deterministic words.
    pub min_entropy: Option<f64>,
    /// Optional minimum length (chars) for the matched secret.
    pub min_length: Option<usize>,
}

/// Process-wide detector list, built lazily on first call.
pub fn detectors() -> &'static [Detector] {
    static DETECTORS: OnceLock<Vec<Detector>> = OnceLock::new();
    DETECTORS.get_or_init(build_detectors)
}

fn r(s: &str) -> Regex {
    Regex::new(s).expect("static detector regex should compile")
}

#[allow(clippy::too_many_lines)]
fn build_detectors() -> Vec<Detector> {
    vec![
        // --- AI provider keys ---------------------------------------------------
        Detector {
            name: "anthropic_api_key",
            description: "Anthropic API key (sk-ant-...).",
            severity: Severity::Critical,
            pattern: r(r"\b(sk-ant-(?:api|admin)\d{2,}-[A-Za-z0-9_-]{32,})"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "openai_api_key",
            description: "OpenAI API key (sk-...).",
            severity: Severity::Critical,
            // OpenAI keys: sk-..., sk-proj-..., sk-svcacct-..., sk-admin-...
            pattern: r(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})"),
            min_entropy: Some(3.5),
            min_length: Some(20),
        },
        Detector {
            name: "voyage_api_key",
            description: "Voyage AI API key (pa-...).",
            severity: Severity::High,
            pattern: r(r"\b(pa-[A-Za-z0-9_-]{40,})"),
            min_entropy: Some(3.5),
            min_length: None,
        },
        Detector {
            name: "cohere_api_key",
            description: "Cohere API key.",
            severity: Severity::High,
            // Cohere keys are ~40 char base64ish strings; surface only when
            // a "cohere" identifier is on the line to keep precision up.
            pattern: r(r#"(?i)cohere[^"'\n]{0,40}["']?([A-Za-z0-9]{40})\b"#),
            min_entropy: Some(3.5),
            min_length: Some(40),
        },
        Detector {
            name: "mistral_api_key",
            description: "Mistral API key.",
            severity: Severity::High,
            pattern: r(r#"(?i)mistral[^"'\n]{0,40}["']?([A-Za-z0-9]{32,40})\b"#),
            min_entropy: Some(3.5),
            min_length: Some(32),
        },
        Detector {
            name: "google_ai_api_key",
            description: "Google AI / Gemini API key (AIza...).",
            severity: Severity::Critical,
            pattern: r(r"\b(AIza[A-Za-z0-9_-]{35})\b"),
            min_entropy: None,
            min_length: None,
        },
        // --- Cloud provider keys -----------------------------------------------
        Detector {
            name: "aws_access_key_id",
            description: "AWS access key ID (AKIA / ASIA / AGPA).",
            severity: Severity::Critical,
            pattern: r(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[A-Z0-9]{16})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "aws_secret_access_key",
            description: "AWS secret access key (40 char b64ish near 'aws').",
            severity: Severity::Critical,
            pattern: r(r#"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[^"'\n]{0,20}["']?([A-Za-z0-9/+=]{40})\b"#),
            min_entropy: Some(4.0),
            min_length: Some(40),
        },
        Detector {
            name: "gcp_service_account_key",
            description: "Google Cloud service-account private-key JSON marker.",
            severity: Severity::Critical,
            pattern: r(r#"("private_key_id"\s*:\s*"[a-f0-9]{40}")"#),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "azure_client_secret",
            description: "Azure AD client secret (high-entropy near AZURE_CLIENT_SECRET).",
            severity: Severity::High,
            pattern: r(r#"(?i)azure[_\-]?client[_\-]?secret[^"'\n]{0,20}["']?([A-Za-z0-9~._\-]{34,})"#),
            min_entropy: Some(4.0),
            min_length: Some(34),
        },
        // --- Developer-platform tokens -----------------------------------------
        Detector {
            name: "github_pat",
            description: "GitHub personal access / fine-grained / OAuth / App installation token.",
            severity: Severity::Critical,
            // Covers ghp_ (classic PAT), gho_ (OAuth), ghu_ (user-to-server),
            // ghs_ (server-to-server / App installation), ghr_ (refresh).
            pattern: r(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "slack_bot_token",
            description: "Slack bot/user/app token (xoxb / xoxp / xoxa / xoxs / xoxr).",
            severity: Severity::Critical,
            pattern: r(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "slack_webhook_url",
            description: "Slack incoming webhook URL.",
            severity: Severity::High,
            pattern: r(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "stripe_live_key",
            description: "Stripe live secret/restricted key.",
            severity: Severity::Critical,
            pattern: r(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "stripe_test_key",
            description: "Stripe test secret/restricted key.",
            severity: Severity::Low,
            pattern: r(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "private_key_pem",
            description: "PEM-armoured private key block opener.",
            severity: Severity::Critical,
            pattern: r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "jwt_token",
            description: "JWT (header.payload.signature, base64url).",
            severity: Severity::Medium,
            pattern: r(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "npm_token",
            description: "NPM access token.",
            severity: Severity::High,
            pattern: r(r"\b(npm_[A-Za-z0-9]{36})\b"),
            min_entropy: None,
            min_length: None,
        },
        // --- Generic high-entropy near a sensitive keyword ---------------------
        Detector {
            name: "generic_high_entropy_secret",
            description: "Long high-entropy string near key/token/secret/api keyword.",
            severity: Severity::Medium,
            // Captures group 1: the candidate secret. Looks for an
            // identifier ending in key/token/secret/password followed by
            // `=` or `:` or whitespace, then a quoted-or-not 24+ char
            // base64ish string.
            pattern: r(r#"(?i)(?:api[_-]?key|access[_-]?token|secret(?:[_-]?key)?|auth[_-]?token|password|passwd|bearer)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{24,})["']?"#),
            min_entropy: Some(4.0),
            min_length: Some(24),
        },
    ]
}

/// Shannon entropy in bits/byte over `s`. Empty input → 0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0f64;
    for c in counts.iter().filter(|&&c| c > 0) {
        let p = *c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Run every detector against `text`, yielding findings keyed by
/// `location` + line. Locations are caller-supplied (path, repo
/// reference, message permalink — whatever's meaningful for the source).
pub fn scan_text(text: &str, location: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        // Cheap pre-filter: skip lines longer than 4 KiB to avoid
        // pathological regex backtracking on minified bundles.
        if line.len() > 4096 {
            continue;
        }
        for det in detectors() {
            for caps in det.pattern.captures_iter(line) {
                let m = caps.get(1).or_else(|| caps.get(0));
                let raw = match m {
                    Some(m) => m.as_str(),
                    None => continue,
                };
                if let Some(min_len) = det.min_length
                    && raw.len() < min_len {
                        continue;
                    }
                if let Some(min_h) = det.min_entropy
                    && shannon_entropy(raw) < min_h {
                        continue;
                    }

                let context = build_context(text, line_idx, raw);
                out.push(Finding {
                    detector: det.name.to_string(),
                    severity: det.severity,
                    location: location.to_string(),
                    line: (line_idx + 1) as u32,
                    raw_match: raw.to_string(),
                    context: Some(context),
                });
            }
        }
    }
    out
}

/// Build a 5-line redacted context window around `line_idx` (±2 lines).
/// The matched secret is replaced by its redacted form *in the context
/// only*; `Finding::raw_match` keeps the original.
fn build_context(text: &str, line_idx: usize, secret: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let lo = line_idx.saturating_sub(2);
    let hi = (line_idx + 3).min(lines.len());
    let mut out = String::new();
    for (i, l) in lines[lo..hi].iter().enumerate() {
        let n = lo + i + 1;
        let marker = if lo + i == line_idx { ">" } else { " " };
        let safe = l.replace(secret, &redact(secret));
        out.push_str(&format!("{} {:>4} | {}\n", marker, n, safe));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_short_string_says_redacted() {
        assert_eq!(redact("short"), "<redacted>");
        assert_eq!(redact("0123456789AB"), "<redacted>");
    }

    #[test]
    fn redact_long_string_keeps_edges() {
        assert_eq!(redact("0123456789ABCDEF"), "0123…CDEF");
    }

    #[test]
    fn shannon_entropy_zero_for_uniform_string() {
        assert_eq!(shannon_entropy(""), 0.0);
        // Single distinct character → 0 bits.
        assert!(shannon_entropy("aaaaaa") < 0.001);
    }

    #[test]
    fn shannon_entropy_higher_for_random_string() {
        // Random base64ish string clears 4.0 comfortably.
        let h = shannon_entropy("aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi");
        assert!(h > 4.0, "expected > 4.0, got {}", h);
    }

    #[test]
    fn detects_anthropic_key() {
        let text = r#"ANTHROPIC_API_KEY="sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW""#;
        let f = scan_text(text, "test");
        assert_eq!(f.len(), 1, "expected one finding, got {:?}", f);
        assert_eq!(f[0].detector, "anthropic_api_key");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_openai_key() {
        // Synthetic high-entropy stand-in (mixed chars to clear the 3.5
        // bits/byte floor; the min_entropy filter would reject a pure
        // A-string of the same length).
        let text = r#"OPENAI_KEY = 'sk-aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234'"#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "openai_api_key"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_aws_keypair() {
        let text = "
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "aws_access_key_id"));
        assert!(f.iter().any(|x| x.detector == "aws_secret_access_key"));
    }

    #[test]
    fn detects_github_pat() {
        let text = "token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "github_pat"));
    }

    #[test]
    fn github_pat_covers_all_token_prefixes() {
        // ghs_ used to have its own dedicated detector that overlapped
        // github_pat 1:1. After removing it, every prefix must still
        // resolve to a single github_pat finding (not zero, not two).
        for prefix in ["ghp", "gho", "ghu", "ghs", "ghr"] {
            let text = format!("token: {}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", prefix);
            let f = scan_text(&text, "test");
            let matches: Vec<_> = f.iter().filter(|x| x.detector == "github_pat").collect();
            assert_eq!(matches.len(), 1, "{prefix}_ must produce exactly one github_pat finding: {f:?}");
        }
    }

    #[test]
    fn detects_slack_bot_token() {
        let text = "SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghijklmnop";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "slack_bot_token"));
    }

    #[test]
    fn detects_slack_webhook() {
        let text = "https://hooks.slack.com/services/T01ABCD/B02EFGH/abcdef1234567890";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "slack_webhook_url"));
    }

    #[test]
    fn detects_pem_private_key() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE…\n";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "private_key_pem"));
    }

    #[test]
    fn generic_high_entropy_only_fires_with_keyword() {
        // Without a "key/token/secret" keyword on the same line, a
        // long base64-ish string should NOT trip the generic detector.
        let plain = "let buffer = aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi;";
        let f = scan_text(plain, "test");
        assert!(
            !f.iter().any(|x| x.detector == "generic_high_entropy_secret"),
            "false positive: {:?}",
            f
        );

        let with_kw = r#"api_key="aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi""#;
        let f2 = scan_text(with_kw, "test");
        assert!(
            f2.iter().any(|x| x.detector == "generic_high_entropy_secret"),
            "missed real secret: {:?}",
            f2
        );
    }

    #[test]
    fn generic_detector_rejects_low_entropy_value() {
        // Looks like assignment, but the value is too low-entropy to be
        // a key (repeated chars).
        let text = r#"api_key="aaaaaaaaaaaaaaaaaaaaaaaaaa""#;
        let f = scan_text(text, "test");
        assert!(!f.iter().any(|x| x.detector == "generic_high_entropy_secret"));
    }

    #[test]
    fn finding_fingerprint_is_stable_for_same_secret() {
        let mut t = String::from("anthropic = 'sk-ant-api03-AAAA");
        t.push_str(&"A".repeat(40));
        t.push('\'');
        let f1 = scan_text(&t, "loc-1");
        let f2 = scan_text(&t, "loc-2");
        assert_eq!(f1[0].fingerprint(), f2[0].fingerprint());
    }

    #[test]
    fn context_window_redacts_secret_in_place() {
        let text = "before\nANTHROPIC_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW\nafter";
        let f = scan_text(text, "test");
        let ctx = f[0].context.as_ref().unwrap();
        // Original secret must NOT appear in context (it should be redacted).
        assert!(!ctx.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        // Redaction marker should appear instead.
        assert!(ctx.contains("…"));
    }
}
