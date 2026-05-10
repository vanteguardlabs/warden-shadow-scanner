//! Local filesystem source.
//!
//! Walks a directory using ripgrep's `ignore` crate so `.gitignore` and
//! `.git/` are respected by default — without that, scans of typical
//! repos drown in `node_modules` / `target/` / `.venv`.
//!
//! Each text file under `MAX_FILE_BYTES` is read and scanned. Binaries
//! are skipped via a NUL-byte heuristic (the same trick git uses).
//!
//! `ignore`'s walker is synchronous, so we drive it via
//! [`tokio::task::spawn_blocking`] to avoid stalling the runtime.

use super::{looks_binary, MAX_FILE_BYTES};
use crate::detector::{scan_text, Finding};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Scan `root` recursively. Returns every finding from every text file
/// the walker visits. Errors during a single file are logged and the
/// scan continues — we don't want one unreadable file to wedge an
/// org-wide scan.
pub async fn scan_directory(root: &Path) -> Result<Vec<Finding>> {
    let root = root.to_path_buf();
    // The `ignore` walker is synchronous. Push the whole walk onto the
    // blocking pool; we collect a `Vec<PathBuf>` first, then read +
    // scan asynchronously. Trading a small upfront allocation for a
    // simpler async story.
    let paths: Vec<PathBuf> = tokio::task::spawn_blocking(move || gather_paths(&root))
        .await
        .context("spawn_blocking gather_paths")??;

    let mut findings = Vec::new();
    for path in paths {
        match scan_one_file(&path).await {
            Ok(mut fs) => findings.append(&mut fs),
            Err(e) => tracing::warn!("skip {}: {}", path.display(), e),
        }
    }
    Ok(findings)
}

fn gather_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let walker = ignore::WalkBuilder::new(root)
        .standard_filters(true)
        .hidden(false) // we *do* want to look at dotfiles like .env
        .build();

    let mut out = Vec::new();
    for dent in walker {
        let dent = match dent {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("walk error: {}", e);
                continue;
            }
        };
        let path = dent.path();
        // Skip symlinks (no recursion into them) and non-files.
        match dent.file_type() {
            Some(ft) if ft.is_file() => {}
            _ => continue,
        }
        // Defer the size + binary heuristics to scan_one_file; here we
        // just collect candidate paths.
        out.push(path.to_path_buf());
    }
    Ok(out)
}

async fn scan_one_file(path: &Path) -> Result<Vec<Finding>> {
    let metadata = tokio::fs::metadata(path).await.with_context(|| format!("stat {}", path.display()))?;
    if metadata.len() > MAX_FILE_BYTES {
        tracing::debug!("skip oversized {} ({} bytes)", path.display(), metadata.len());
        return Ok(Vec::new());
    }
    let bytes = tokio::fs::read(path).await.with_context(|| format!("read {}", path.display()))?;
    if looks_binary(&bytes) {
        tracing::debug!("skip binary {}", path.display());
        return Ok(Vec::new());
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()), // not UTF-8, skip
    };
    Ok(scan_text(text, &path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn scans_planted_secret_in_subdir() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("subdir");
        fs::create_dir_all(&nested).unwrap();
        // Plant a high-confidence vendor key — pattern matches without
        // entropy gating.
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        fs::write(nested.join(".env"), format!("ANTHROPIC_API_KEY={}\n", key)).unwrap();

        let findings = scan_directory(dir.path()).await.unwrap();
        assert!(
            findings.iter().any(|f| f.detector == "anthropic_api_key"),
            "no anthropic finding: {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn respects_gitignore() {
        let dir = tempdir().unwrap();
        // Stand up a fake repo: .gitignore excludes node_modules.
        fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let key = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-cZbYaXdW";
        fs::write(
            dir.path().join("node_modules/leaked.env"),
            format!("ANTHROPIC_API_KEY={}", key),
        )
        .unwrap();

        // For the ignore crate to respect .gitignore, the dir must look
        // like a git repo OR we must ask explicitly. WalkBuilder honours
        // .gitignore even without .git/, so this is enough.
        // BUT we need a `.git` marker dir for some `ignore` defaults to
        // pick up the file — depends on version. Add an empty .git for
        // robustness.
        fs::create_dir_all(dir.path().join(".git")).unwrap();

        let findings = scan_directory(dir.path()).await.unwrap();
        assert!(
            !findings.iter().any(|f| f.location.contains("node_modules")),
            "ignored path leaked into findings: {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn skips_oversized_file() {
        let dir = tempdir().unwrap();
        // Build a >1MiB file ending with what would otherwise be a hit.
        let mut buf = "x".repeat((MAX_FILE_BYTES + 1024) as usize);
        buf.push_str("\nANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW\n");
        fs::write(dir.path().join("big.txt"), buf).unwrap();
        let findings = scan_directory(dir.path()).await.unwrap();
        assert!(findings.is_empty(), "scanned an oversized file: {:?}", findings);
    }

    #[tokio::test]
    async fn skips_binary_file() {
        let dir = tempdir().unwrap();
        // NUL byte + valid-looking key after = binary heuristic should
        // skip the whole file.
        let mut buf: Vec<u8> = b"\x00binary marker\n".to_vec();
        buf.extend_from_slice(
            b"ANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW\n",
        );
        fs::write(dir.path().join("opaque.bin"), buf).unwrap();
        let findings = scan_directory(dir.path()).await.unwrap();
        assert!(findings.is_empty(), "binary file scanned: {:?}", findings);
    }
}
