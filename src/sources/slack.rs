//! Slack source. Auth via `SLACK_BOT_TOKEN` (`xoxb-…`). Required scopes:
//!
//! * `channels:read` (and `groups:read` for private channels the bot is in),
//! * `channels:history` (+ `groups:history`, `mpim:history`, `im:history`),
//! * `users:read` (optional — only used to attribute findings to a user).
//!
//! Threads, archived channels, and external shared channels are
//! intentionally out of scope for the MVP — covering them adds API
//! surface without much marginal lift over "did anyone paste a key into
//! a public channel."

use crate::detector::{scan_text, Finding};
use anyhow::{bail, Context, Result};
use chrono::{Duration as CDuration, Utc};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::Deserialize;

const USER_AGENT_VALUE: &str = "warden-shadow-scanner/0.1";

/// How far back to look by default. 14 days covers "did someone paste
/// a key in the last sprint" without burning rate limit on ancient
/// noise. CLI exposes a `--days` knob to override.
pub const DEFAULT_LOOKBACK_DAYS: i64 = 14;

#[derive(Debug, Clone)]
pub struct SlackClient {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl SlackClient {
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("SLACK_BOT_TOKEN")
            .context("SLACK_BOT_TOKEN must be set for the slack source")?;
        Ok(Self {
            http: reqwest::Client::new(),
            token,
            base_url: "https://slack.com/api".into(),
        })
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.token)).expect("valid token"),
        );
        h.insert(reqwest::header::USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        h
    }

    /// List conversations the bot is a member of. Cursors through
    /// pages until exhausted.
    pub async fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/users.conversations?limit=200&types=public_channel,private_channel",
                self.base_url
            );
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={}", urlencoding(c)));
            }
            let resp: ListConversationsResponse = self.get_json(&url).await?;
            if !resp.ok {
                bail!("slack list_conversations: {}", resp.error.unwrap_or_default());
            }
            out.extend(resp.channels);
            match resp.response_metadata.and_then(|m| m.next_cursor) {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Pull message history for `channel_id` since `since_ts` (seconds
    /// since epoch). Returns messages newest-first, as Slack does.
    pub async fn fetch_history(&self, channel_id: &str, since_ts: f64) -> Result<Vec<SlackMessage>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/conversations.history?channel={}&oldest={}&limit=200",
                self.base_url, channel_id, since_ts
            );
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={}", urlencoding(c)));
            }
            let resp: HistoryResponse = self.get_json(&url).await?;
            if !resp.ok {
                bail!("slack history {}: {}", channel_id, resp.error.unwrap_or_default());
            }
            out.extend(resp.messages);
            match resp.response_metadata.and_then(|m| m.next_cursor) {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let resp = self
            .http
            .get(url)
            .headers(self.headers())
            .send()
            .await
            .with_context(|| format!("GET {}", url))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("GET {} -> {}: {}", url, status, body);
        }
        // Slack returns `{ ok: false, error: "..." }` with a 200 status,
        // so we need to deserialize first and then check the `ok` field
        // upstream. The inner type carries that boolean.
        resp.json().await.with_context(|| format!("decode {}", url))
    }
}

/// Minimal URL-encoder for Slack cursor values. Cursors are opaque
/// base64-ish strings; we only need to escape `+`, `/`, `=`, and the
/// occasional `&`.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

#[derive(Debug, Clone, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub is_archived: bool,
    #[serde(default)]
    pub is_member: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlackMessage {
    #[serde(default)]
    pub text: String,
    pub ts: String,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListConversationsResponse {
    ok: bool,
    #[serde(default)]
    channels: Vec<Conversation>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    response_metadata: Option<ResponseMetadata>,
}

#[derive(Debug, Deserialize)]
struct HistoryResponse {
    ok: bool,
    #[serde(default)]
    messages: Vec<SlackMessage>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    response_metadata: Option<ResponseMetadata>,
}

#[derive(Debug, Deserialize)]
struct ResponseMetadata {
    #[serde(default)]
    next_cursor: Option<String>,
}

/// Top-level driver: scan every conversation the bot is a member of,
/// looking back `lookback_days` days. Skips archived channels.
pub async fn scan_workspace(client: &SlackClient, lookback_days: i64) -> Result<Vec<Finding>> {
    let conversations = client.list_conversations().await?;
    let since = (Utc::now() - CDuration::days(lookback_days))
        .timestamp() as f64;

    let mut findings = Vec::new();
    for conv in conversations {
        if conv.is_archived || !conv.is_member {
            continue;
        }
        let label = conv.name.clone().unwrap_or_else(|| conv.id.clone());
        match client.fetch_history(&conv.id, since).await {
            Ok(messages) => {
                for msg in messages {
                    if msg.text.is_empty() {
                        continue;
                    }
                    let location = format!("slack://{}/{}", label, msg.ts);
                    findings.extend(scan_text(&msg.text, &location));
                }
                tracing::info!("scanned slack channel {}", label);
            }
            Err(e) => tracing::warn!("skip slack channel {}: {}", label, e),
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_preserves_unreserved() {
        assert_eq!(urlencoding("abcXYZ012-_.~"), "abcXYZ012-_.~");
    }

    #[test]
    fn urlencoding_escapes_special() {
        assert_eq!(urlencoding("a/b+c=d"), "a%2Fb%2Bc%3Dd");
    }
}
