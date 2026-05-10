//! Per-platform fetchers. Every source produces `(location, text)`
//! pairs for the [`crate::detector`] engine.

pub mod local;
pub mod github;
pub mod slack;

/// Cap on individual file size, in bytes. 1 MiB covers virtually every
/// hand-edited config / source file; anything bigger is almost certainly
/// generated (lockfiles, minified bundles, fixtures) and not worth the
/// regex time.
pub(crate) const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) const USER_AGENT_VALUE: &str = "warden-shadow-scanner/0.1";

/// `git`-style binary detection: any NUL byte in the first 8 KiB means
/// "treat as binary." UTF-8 can't contain NUL, so a positive hit rules
/// out source code.
pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}
