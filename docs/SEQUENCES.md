# warden-shadow-scanner sequence diagrams

Five sequence diagrams covering the wire-level paths the scanner can
take: CLI dispatch + the shared `emit` pipeline, the gitignore-aware
local-filesystem scan, the GitHub org / repo scan with rate-limit
backoff, the Slack workspace scan, and the per-line detector engine
that turns matched bytes into a deduped `Report`. A flowchart at the
end captures the request decision tree (source × output × severity
filter × exit code).

The scanner is a single CLI binary, so the diagrams highlight the
boundaries it crosses: the local filesystem (via the `ignore` crate),
`api.github.com` (REST + ETag-free polling), `slack.com/api`
(cursored history), and stdout (human / JSON / SARIF).

## 1. CLI dispatch + the shared `emit` pipeline

`main` reads as a sequential pipeline: tracing init (default `warn`)
→ clap `Cli::parse` → dispatch to one of three async runners → each
calls `emit(source, findings, OutputArgs)` to filter, group, and
format → exit 0/2 by `any_high` aggregation. `OutputArgs` is
`#[command(flatten)]`-ed onto every subcommand so the surface is
identical across `local`, `github`, and `slack`.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator shell
    participant Main as main
    participant Cli as clap Cli::parse
    participant Run as run_local / run_github / run_slack
    participant Src as sources::mod::scan_*
    participant Emit as emit
    participant Sev as Severity::from_min + filter_by_min_severity
    participant Rep as Report::from_findings
    participant Out as write_human / write_json / write_sarif

    Op->>Main: warden-shadow-scanner subcommand [...]
    Main->>Main: tracing_subscriber::registry + EnvFilter (default warn, stderr writer)
    Main->>Cli: parse argv + env
    Cli-->>Main: Cli { command, OutputArgs { json, sarif, unredacted, severity_min } }
    alt Command::Local
        Main->>Run: run_local(path, out)
        Run->>Src: sources::local::scan_directory(path)
    else Command::Github
        Main->>Run: run_github(owner_arg, include_forks, include_archived, out)
        Run->>Run: split owner/repo on first '/'
        Run->>Src: sources::github::scan_owner(client, owner, repo_filter, include_forks, include_archived)
    else Command::Slack
        Main->>Run: run_slack(days, out)
        Run->>Src: sources::slack::scan_workspace(client, lookback_days)
    end
    Src-->>Run: VecFinding (raw, possibly multi-detector per line)
    Run->>Emit: emit(source_label, findings, out)
    Emit->>Sev: Severity::from_min(out.severity_min) — error if invalid
    Sev->>Emit: Severity enum
    Emit->>Sev: filter_by_min_severity(findings, min)
    Sev-->>Emit: filtered VecFinding
    Emit->>Rep: from_findings(source, filtered, unredacted && !sarif)
    Note over Emit: SARIF always overrides --unredacted — SARIF outputs end up as CI artefacts
    Rep-->>Emit: Report { source, scanned_at, aggregates, total_findings }
    alt out.sarif
        Emit->>Out: report.write_sarif(stdout)
    else out.json
        Emit->>Out: report.write_json(stdout)
    else
        Emit->>Out: report.write_human(stdout, unredacted)
    end
    Out-->>Op: stdout payload
    Emit->>Emit: any_high = aggregates.iter().any(Critical or High)
    alt any_high
        Emit-->>Op: process::exit(2)  — CI-friendly
    else no critical or high (or filtered out)
        Emit-->>Op: exit 0
    end
    Note over Main,Op: runtime errors (bad auth, network) surface via anyhow → exit 1
```

## 2. `local` — gitignore-aware filesystem walk

`scan_directory` pushes the synchronous `ignore::WalkBuilder` walk
onto the blocking pool, collects every candidate path into a Vec,
then reads + scans each file asynchronously. Per-file the metadata
size cap, the NUL-byte binary heuristic, and the UTF-8 check all
short-circuit before any regex work. Individual file failures
`warn`-log and continue — one unreadable file never wedges an
org-wide scan.

```mermaid
sequenceDiagram
    autonumber
    participant Run as run_local
    participant Scan as scan_directory
    participant Gather as gather_paths (spawn_blocking)
    participant Ignore as ignore::WalkBuilder
    participant Tokio as tokio::fs
    participant Det as scan_text

    Run->>Scan: scan_directory(root: &Path)
    Scan->>Gather: tokio::task::spawn_blocking gather_paths(root.clone)
    activate Gather
    Gather->>Ignore: WalkBuilder::new(root).standard_filters(true).hidden(false).build
    Note over Ignore: .gitignore-aware,<br/>still descends into dotfiles like .env
    loop walker entries
        Ignore-->>Gather: DirEntry or error
        alt walk error
            Gather->>Gather: tracing::warn — walk error — continue
        else file_type == file
            Gather->>Gather: out.push(path.to_path_buf)
        else dir / symlink / other
            Gather->>Gather: skip
        end
    end
    Gather-->>Scan: VecPathBuf
    deactivate Gather
    loop every collected path
        Scan->>Scan: scan_one_file(path)
        Scan->>Tokio: metadata(path)
        alt metadata err
            Tokio-->>Scan: Err
            Scan->>Scan: tracing::warn skip path — continue
        else size > MAX_FILE_BYTES
            Tokio-->>Scan: metadata.len() > MAX_FILE_BYTES
            Scan->>Scan: tracing::debug skip oversized — return Vec::new
        end
        Scan->>Tokio: read(path)
        Tokio-->>Scan: bytes
        Scan->>Scan: looks_binary (NUL-byte heuristic, same as git uses)
        alt binary
            Scan->>Scan: tracing::debug skip binary — return Vec::new
        end
        Scan->>Scan: std::str::from_utf8(&bytes) — not UTF-8 → return Vec::new
        Scan->>Det: scan_text(text, path.display.to_string)
        Det-->>Scan: VecFinding
        Scan->>Scan: findings.append(&mut fs)
    end
    Scan-->>Run: VecFinding
```

## 3. `github` — owner-or-repo scan with rate-limit backoff

`GitHubClient::from_env` pulls an optional `GITHUB_TOKEN` (unset
falls back to the 60-req/hour public ceiling). `scan_owner` either
fetches one named repo or paginates `/orgs/{owner}/repos` →
`/users/{owner}/repos` (whichever returns non-empty wins; both
errors bubble up with context). Every HTTP call goes through a
retry-on-rate-limit loop that respects `X-RateLimit-Reset` and
sleeps on 429 with a 30s backoff.

```mermaid
sequenceDiagram
    autonumber
    participant Run as run_github
    participant Cli as GitHubClient::from_env
    participant Scan as scan_owner
    participant List as list_repos / paginate_repos
    participant Tree as list_tree
    participant Blob as fetch_blob (get_raw)
    participant Det as scan_text
    participant Gh as api.github.com

    Run->>Cli: from_env — reads GITHUB_TOKEN (Option), base_url default
    Cli-->>Run: GitHubClient
    Run->>Run: split owner_arg on '/' → (owner, Optionrepo)
    Run->>Scan: scan_owner(client, owner, repo_filter, include_forks, include_archived)
    alt repo_filter is Some(name)
        Scan->>Gh: GET /repos/{owner}/{name} (via get_json + retry loop)
        Gh-->>Scan: RepoSummary
    else
        Scan->>List: list_repos(owner)
        loop endpoints [/orgs/{owner}/repos, /users/{owner}/repos]
            List->>List: paginate_repos(url)
            loop while next Link rel=next
                List->>Gh: GET url + Bearer GITHUB_TOKEN + Accept: application/vnd.github+json
                alt 403 + X-RateLimit-Remaining: 0
                    Gh-->>List: 403 + reset header
                    List->>List: sleep clamp(reset - now, 1, 600) — retry
                else 429
                    Gh-->>List: 429
                    List->>List: sleep 30s — retry
                else non-2xx
                    Gh-->>List: status + body
                    List-->>Scan: bail err
                else 2xx
                    Gh-->>List: page JSON + Link header
                    List->>List: parse next_link — all.extend(page)
                end
            end
            List-->>Scan: VecRepoSummary (or last_err carried forward)
            alt non-empty
                Scan->>Scan: use this list, stop iterating endpoints
            end
        end
    end
    loop every repo
        alt !include_forks AND repo.fork
            Scan->>Scan: skip
        else !include_archived AND repo.archived
            Scan->>Scan: skip
        else
            Scan->>Tree: list_tree(owner, repo.name, repo.default_branch)
            Tree->>Gh: GET /repos/.../git/trees/{branch}?recursive=1
            Gh-->>Tree: TreeResponse (filtered to kind == blob)
            Tree-->>Scan: VecTreeEntry
            loop every blob
                alt size > MAX_FILE_BYTES OR has_binary_extension(path)
                    Scan->>Scan: skip
                else
                    Scan->>Blob: fetch_blob(owner, repo, path, branch)
                    Blob->>Gh: GET /repos/.../contents/{path}?ref={branch} + Accept: application/vnd.github.raw
                    Gh-->>Blob: raw bytes (rate-limit-loop applies)
                    Blob-->>Scan: bytes
                    Scan->>Scan: looks_binary OR utf8 decode fail → skip
                    Scan->>Det: scan_text(text, "{owner}/{repo}:{path}@{branch}")
                    Det-->>Scan: VecFinding
                    Scan->>Scan: out.extend(findings)
                end
            end
        end
    end
    Scan-->>Run: VecFinding
```

## 4. `slack` — workspace scan with cursor-paginated history

`SlackClient::from_env` requires `SLACK_BOT_TOKEN` (errors out at
boot if unset — required scopes documented in
`src/sources/slack.rs`). `scan_workspace` lists every conversation
the bot is a member of (cursor-paginated), skips archived /
non-member rooms, then pages `conversations.history` for each
remaining channel back to `now - lookback_days`. Slack returns
`{ ok: false, error }` with a 200 status, so every paged response is
parsed and the `ok` flag inspected before consuming `messages`.

```mermaid
sequenceDiagram
    autonumber
    participant Run as run_slack
    participant Cli as SlackClient::from_env
    participant Scan as scan_workspace
    participant Conv as list_conversations
    participant Hist as fetch_history
    participant Det as scan_text
    participant Sl as slack.com/api

    Run->>Cli: from_env — SLACK_BOT_TOKEN required else bail
    Cli-->>Run: SlackClient (base https://slack.com/api)
    Run->>Scan: scan_workspace(client, lookback_days)
    Scan->>Conv: list_conversations
    loop until response_metadata.next_cursor empty
        Conv->>Sl: GET /users.conversations?limit=200&types=public_channel,private_channel + Bearer token
        Sl-->>Conv: { ok, channels, response_metadata: { next_cursor } }
        alt ok == false
            Conv-->>Scan: bail slack list_conversations: <error>
        else
            Conv->>Conv: out.extend(channels) — set cursor or break
        end
    end
    Conv-->>Scan: VecConversation
    Scan->>Scan: since_ts = Utc::now - Duration::days(lookback_days)
    loop every conversation
        alt conv.is_archived OR !conv.is_member
            Scan->>Scan: skip
        else
            Scan->>Hist: fetch_history(channel_id, since_ts)
            loop until next_cursor empty
                Hist->>Sl: GET /conversations.history?channel=...&oldest=since_ts&limit=200 + Bearer
                Sl-->>Hist: { ok, messages, response_metadata }
                alt ok == false
                    Hist-->>Scan: bail slack history <id>: <error>
                else
                    Hist->>Hist: out.extend(messages) — set cursor or break
                end
            end
            Hist-->>Scan: VecSlackMessage
            loop every message
                alt msg.text.is_empty
                    Scan->>Scan: skip
                else
                    Scan->>Det: scan_text(msg.text, "slack://{channel_label}/{ts}")
                    Det-->>Scan: VecFinding
                    Scan->>Scan: findings.extend
                end
            end
            Scan->>Scan: tracing::info scanned slack channel <label>
        end
    end
    Note over Hist,Scan: per-channel fetch_history error → warn and skip that channel — whole-workspace scan continues
    Scan-->>Run: VecFinding
```

## 5. Detector engine — `scan_text` + `Report::from_findings`

The detector engine is shared by all three sources. For every line
under 4 KiB (pathological-regex guard), every detector's regex runs;
matches that clear `min_length` and `min_entropy` (Shannon, bits per
byte) produce a `Finding` with a ±2-line redacted context window.
`Report::from_findings` then groups by SHA-256 fingerprint of the
raw secret (so the same key in 12 files becomes one entry with 12
locations), dedupes inside an aggregate by `(location, line)` to
collapse the vendor-vs-generic-backstop overlap, and keeps the
highest-severity detector name on conflict.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as source::scan_*
    participant Scan as scan_text
    participant Det as Detector (per entry in detectors())
    participant H as shannon_entropy
    participant Ctx as build_context
    participant Rep as Report::from_findings
    participant FP as Finding::fingerprint (sha256[..8])

    Caller->>Scan: scan_text(text, location)
    loop every line (idx, line)
        alt line.len > 4096
            Scan->>Scan: skip — pathological backtracking guard
        else
            loop every detector
                Scan->>Det: pattern.captures_iter(line)
                loop every captured match
                    Det-->>Scan: caps.get(1).or(caps.get(0))
                    alt min_length set AND raw.len < min_length
                        Scan->>Scan: skip
                    else min_entropy set
                        Scan->>H: shannon_entropy(raw)
                        H-->>Scan: bits/byte
                        alt entropy < min_entropy
                            Scan->>Scan: skip — suppresses identifiers that look pattern-shaped
                        end
                    end
                    Scan->>Ctx: build_context(text, line_idx, raw)
                    Ctx->>Ctx: lines[lo..hi] with secret replaced by redact(secret) inline
                    Ctx-->>Scan: 5-line redacted window
                    Scan->>Scan: out.push Finding { detector, severity, location, line: idx+1, raw_match, context }
                end
            end
        end
    end
    Scan-->>Caller: VecFinding

    Caller->>Rep: Report::from_findings(source, findings, unredacted)
    loop every finding
        Rep->>FP: f.fingerprint — sha256(raw_match)[..8] hex
        FP-->>Rep: fingerprint string
        Rep->>Rep: BTreeMap entry-or-insert Aggregate { fingerprint, detector, severity, redacted(raw), raw: Some(raw) if unredacted, locations: [] }
        alt f.severity < entry.severity
            Rep->>Rep: entry.severity = f.severity — entry.detector = f.detector — higher tier wins
        end
        alt locations contains (location, line)
            Rep->>Rep: skip — vendor and generic backstop fired on same physical hit
        else
            Rep->>Rep: entry.locations.push Location { location, line, context }
        end
    end
    Rep->>Rep: collect into Vec — sort by (severity ASC, detector, fingerprint) for stable diff
    Rep-->>Caller: Report { source, scanned_at: Utc::now, aggregates, total_findings }
```

## 6. Request decision tree (flowchart)

A single CLI invocation fans out across four orthogonal knobs: the
source subcommand, the output format, the redaction posture, and
the severity-min cutoff. The exit code then comes from whether any
surviving aggregate is Critical or High.

```mermaid
flowchart TD
    Start([warden-shadow-scanner subcommand ...]) --> Tracing[tracing_subscriber init<br/>RUST_LOG default warn<br/>stderr writer]
    Tracing --> Parse[clap Cli parse + OutputArgs flatten]
    Parse --> Sub{subcommand}

    Sub -->|local path| L[sources::local::scan_directory<br/>spawn_blocking ignore::WalkBuilder<br/>per-file size + binary + utf8 gates]
    Sub -->|github owner or owner/repo| G[sources::github::scan_owner<br/>GITHUB_TOKEN optional, 60 rph fallback<br/>orgs then users endpoint fallback<br/>rate-limit + 429 retry loop]
    Sub -->|slack --days N| S[sources::slack::scan_workspace<br/>SLACK_BOT_TOKEN required else bail<br/>cursored list_conversations + fetch_history<br/>skip archived + non-member]

    L --> Det[scan_text per file<br/>line under 4 KiB<br/>regex captures<br/>min_length + min_entropy gates<br/>build_context with inline redact]
    G --> Det
    S --> Det

    Det --> Emit[emit source, findings, out]
    Emit --> SevMin{Severity::from_min<br/>valid?}
    SevMin -->|no| Err1[exit 1 — anyhow context]
    SevMin -->|yes| Filter[filter_by_min_severity]
    Filter --> Build[Report::from_findings<br/>BTreeMap fingerprint dedupe<br/>location, line collapse<br/>higher-severity detector wins]

    Build --> Fmt{output format}
    Fmt -->|--sarif| Sarif[write_sarif<br/>always redacted, ignores --unredacted<br/>fingerprint as warden/v1 stable id]
    Fmt -->|--json| Json[write_json<br/>raw field present only if unredacted]
    Fmt -->|default| Human[write_human<br/>banner if unredacted<br/>cap locations at 5, suggest --json]

    Sarif --> AnyHigh{any aggregate<br/>Critical or High?}
    Json --> AnyHigh
    Human --> AnyHigh
    AnyHigh -->|yes| E2[process::exit 2 — CI-friendly]
    AnyHigh -->|no| E0[exit 0]

    Err1 --> End([process exits])
    E0 --> End
    E2 --> End
```
