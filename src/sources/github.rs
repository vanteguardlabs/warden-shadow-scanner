//! GitHub source. Calls the REST API directly via `reqwest` — no SDK dep.
//!
//! Auth comes from the `GITHUB_TOKEN` env var (PAT or GitHub App token).
//! Without a token we still hit the public API — useful for "scan a
//! public repo" demos — but rate-limit drops to 60 req/hour.
//!
//! Rate-limit handling: 403 with `X-RateLimit-Remaining: 0` sleeps until
//! `X-RateLimit-Reset`; 429 backs off 30s; anything else surfaces.

use crate::detector::{scan_text, Finding};
use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use std::time::Duration;

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
const USER_AGENT_VALUE: &str = "warden-shadow-scanner/0.1";

#[derive(Debug, Clone)]
pub struct GitHubClient {
    http: reqwest::Client,
    token: Option<String>,
    /// Override base URL for tests (default `https://api.github.com`).
    base_url: String,
}

impl GitHubClient {
    pub fn from_env() -> Self {
        Self {
            http: reqwest::Client::new(),
            token: std::env::var("GITHUB_TOKEN").ok(),
            base_url: "https://api.github.com".into(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        h.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        if let Some(t) = &self.token {
            // `Bearer` is the modern PAT scheme; `token` is the legacy
            // form. GitHub accepts both for classic PATs.
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", t)) {
                h.insert(AUTHORIZATION, v);
            }
        }
        h
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        loop {
            let resp = self
                .http
                .get(url)
                .headers(self.headers())
                .send()
                .await
                .with_context(|| format!("GET {}", url))?;
            if let Some(wait) = rate_limit_backoff(&resp).await? {
                tokio::time::sleep(wait).await;
                continue;
            }
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                bail!("GET {} -> {}: {}", url, status, body);
            }
            return resp.json().await.with_context(|| format!("decode {}", url));
        }
    }

    async fn get_raw(&self, url: &str) -> Result<Vec<u8>> {
        loop {
            let resp = self
                .http
                .get(url)
                .headers({
                    // `application/vnd.github.raw` returns the file body
                    // directly instead of base64-wrapped JSON.
                    let mut h = self.headers();
                    h.insert(ACCEPT, HeaderValue::from_static("application/vnd.github.raw"));
                    h
                })
                .send()
                .await
                .with_context(|| format!("GET raw {}", url))?;
            if let Some(wait) = rate_limit_backoff(&resp).await? {
                tokio::time::sleep(wait).await;
                continue;
            }
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                bail!("GET raw {} -> {}: {}", url, status, body);
            }
            return Ok(resp.bytes().await?.to_vec());
        }
    }

    /// List every repo under `owner` (org or user). Walks paginated
    /// `/orgs/{owner}/repos` first; if that 404s, falls back to
    /// `/users/{owner}/repos`.
    pub async fn list_repos(&self, owner: &str) -> Result<Vec<RepoSummary>> {
        let mut out = Vec::new();
        let endpoints = [
            format!("{}/orgs/{}/repos?per_page=100&type=all", self.base_url, owner),
            format!("{}/users/{}/repos?per_page=100&type=all", self.base_url, owner),
        ];
        for ep in endpoints {
            match self.paginate_repos(ep.clone()).await {
                Ok(v) => {
                    out = v;
                    if !out.is_empty() {
                        return Ok(out);
                    }
                }
                Err(e) => tracing::debug!("repo list {} failed: {}", ep, e),
            }
        }
        Ok(out)
    }

    async fn paginate_repos(&self, mut url: String) -> Result<Vec<RepoSummary>> {
        let mut all = Vec::new();
        loop {
            let resp = self
                .http
                .get(&url)
                .headers(self.headers())
                .send()
                .await
                .with_context(|| format!("GET {}", url))?;
            if let Some(wait) = rate_limit_backoff(&resp).await? {
                tokio::time::sleep(wait).await;
                continue;
            }
            let status = resp.status();
            let next = next_link(&resp);
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                bail!("GET {} -> {}: {}", url, status, body);
            }
            let page: Vec<RepoSummary> = resp.json().await?;
            all.extend(page);
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        Ok(all)
    }

    /// Recursive tree listing for a repo at a given branch. Returns
    /// every blob path (no directories).
    pub async fn list_tree(&self, owner: &str, repo: &str, branch: &str) -> Result<Vec<TreeEntry>> {
        let url = format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            self.base_url, owner, repo, branch
        );
        let tree: TreeResponse = self.get_json(&url).await?;
        Ok(tree.tree.into_iter().filter(|t| t.kind == "blob").collect())
    }

    pub async fn get_repo(&self, owner: &str, repo: &str) -> Result<RepoSummary> {
        let url = format!("{}/repos/{}/{}", self.base_url, owner, repo);
        self.get_json(&url).await
    }

    pub async fn fetch_blob(&self, owner: &str, repo: &str, path: &str, branch: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}?ref={}",
            self.base_url, owner, repo, path, branch
        );
        self.get_raw(&url).await
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoSummary {
    pub name: String,
    pub full_name: String,
    pub default_branch: String,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TreeResponse {
    pub tree: Vec<TreeEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub size: Option<u64>,
}

/// Inspect a response for rate-limit / retry signals. Returns `Some(d)`
/// if the caller should sleep for `d` and retry; `None` to proceed.
async fn rate_limit_backoff(resp: &reqwest::Response) -> Result<Option<Duration>> {
    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN
        && resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
            == Some(0)
    {
        let reset = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let now = chrono::Utc::now().timestamp();
        let wait = (reset - now).clamp(1, 600);
        tracing::warn!("github rate-limited; sleeping {}s", wait);
        return Ok(Some(Duration::from_secs(wait as u64)));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        tracing::warn!("github 429; backing off 30s");
        return Ok(Some(Duration::from_secs(30)));
    }
    Ok(None)
}

/// Parse the next-page URL out of a paginated response's `Link` header.
fn next_link(resp: &reqwest::Response) -> Option<String> {
    let link = resp.headers().get("link")?.to_str().ok()?;
    // Header looks like: <url1>; rel="next", <url2>; rel="last"
    for part in link.split(',') {
        let part = part.trim();
        if part.contains(r#"rel="next""#)
            && let Some(start) = part.find('<')
                && let Some(end) = part.find('>') {
                    return Some(part[start + 1..end].to_string());
                }
    }
    None
}

/// Top-level driver: scan every text file in every (non-archived,
/// non-fork by default) repo under `owner`. If `repo_filter` is `Some`,
/// scan only that one repo.
pub async fn scan_owner(
    client: &GitHubClient,
    owner: &str,
    repo_filter: Option<&str>,
    include_forks: bool,
    include_archived: bool,
) -> Result<Vec<Finding>> {
    let repos = match repo_filter {
        Some(name) => vec![client.get_repo(owner, name).await?],
        None => client.list_repos(owner).await?,
    };
    let mut findings = Vec::new();
    for repo in repos {
        if !include_forks && repo.fork {
            continue;
        }
        if !include_archived && repo.archived {
            continue;
        }
        match scan_repo(client, owner, &repo).await {
            Ok(mut fs) => {
                tracing::info!("scanned {}: {} findings", repo.full_name, fs.len());
                findings.append(&mut fs);
            }
            Err(e) => tracing::warn!("skip repo {}: {}", repo.full_name, e),
        }
    }
    Ok(findings)
}

async fn scan_repo(client: &GitHubClient, owner: &str, repo: &RepoSummary) -> Result<Vec<Finding>> {
    let tree = client.list_tree(owner, &repo.name, &repo.default_branch).await?;
    let mut out = Vec::new();
    for entry in tree {
        // Skip oversized blobs and obviously-binary paths.
        if entry.size.unwrap_or(0) > MAX_FILE_BYTES {
            continue;
        }
        if has_binary_extension(&entry.path) {
            continue;
        }
        let bytes = match client.fetch_blob(owner, &repo.name, &entry.path, &repo.default_branch).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!("blob fetch {}/{}: {}", repo.full_name, entry.path, e);
                continue;
            }
        };
        if bytes.iter().take(8192).any(|&b| b == 0) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else { continue };
        let location = format!("{}:{}@{}", repo.full_name, entry.path, repo.default_branch);
        out.extend(scan_text(text, &location));
    }
    Ok(out)
}

fn has_binary_extension(path: &str) -> bool {
    // Lower-case extension suffix match. Cheap; covers >95% of binary
    // file types you'd find in a typical repo.
    let lc = path.to_ascii_lowercase();
    const BIN_EXTS: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff",
        ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".lib",
        ".class", ".jar", ".war", ".ear",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp3", ".mp4", ".wav", ".flac", ".ogg", ".mov", ".avi", ".mkv",
        ".pyc", ".pyo", ".node",
    ];
    BIN_EXTS.iter().any(|ext| lc.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_extensions_recognised() {
        assert!(has_binary_extension("logo.png"));
        assert!(has_binary_extension("icon.ICO"));
        assert!(has_binary_extension("path/to/lib.so"));
        assert!(!has_binary_extension("README.md"));
        assert!(!has_binary_extension("src/main.rs"));
    }

}
