fn required_s2_lanes() -> [&'static str; 5] {
    [
        "identity_engine",
        "injection_engine",
        "ingress_engine",
        "logic_engine",
        "config_engine",
    ]
}

fn s2_lane_complete(lane: &RunbookLane) -> bool {
    lane.status == "done"
}

fn normalize_lane_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "done" | "completed" | "complete" | "success" | "succeeded" => "done",
        "failed" | "failure" | "error" | "errored" => "failed",
        "queued" | "pending" => "queued",
        "retrying" | "backoff" | "rate_limited" | "rate-limited" => "retrying",
        "running" | "started" | "spawned" | "in_progress" | "in-progress" => "running",
        _ => "running",
    }
}

fn surface_label_limit(kind: &str) -> usize {
    if kind == "read_target" {
        240
    } else {
        140
    }
}

fn marker_value(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let trimmed = rest.trim_start();
    if let Some(value) = quoted_marker_value(trimmed) {
        return clean_marker_value(&value);
    }
    let keys = [
        " id=",
        " lane=",
        " mode=",
        " root=",
        " facts=",
        " category=",
        " area=",
        " feature=",
        " family=",
        " role=",
        " sha256=",
        " observed_exit=",
        " debt=",
        " source=",
        " sink=",
        " guard=",
        " file=",
        " endpoints=",
        " route=",
        " source_files=",
        " files=",
        " routes=",
        " path=",
        " read=",
        " endpoint=",
        " lines=",
        " anchor=",
        " follow=",
        " question=",
        " stop_when=",
        " broaden_after=",
        " object_id=",
        " auth_hint=",
        " ownership_hint=",
        " target=",
        " title=",
        " status=",
        " count=",
        " claims=",
        " candidates=",
        " mapped=",
        " total=",
        " result=",
        " reason=",
        " must=",
        " check=",
        " attack=",
        " obligation=",
        " priority=",
        " origin=",
        " cve_prior=",
        " note=",
        " summary=",
        " error=",
        " severity=",
        " code_path=",
        " thread_id=",
        " thread=",
        " evidence=",
        " payload=",
        " poc=",
        " confidence=",
        " exploit=",
        " cwe=",
        " label=",
        " kind=",
        " status=",
        " level=",
        " fingerprint=",
        " root_cause=",
        " precondition=",
        " impact=",
        " next=",
        " positive=",
        " negative=",
        " verification=",
        " merge_into=",
        " merged_into=",
        " surface=",
        " lane_id=",
        " bridge=",
        " bridge_keys=",
        " claim=",
        " claim_id=",
        " atoms=",
        " atom_ids=",
        " verify_plan=",
        " plan=",
        " replay=",
        " expected=",
        " cleanup=",
        " finding=",
        " evidence_refs=",
        " refs=",
        " score=",
        // agent 常用这些同义键名描述 PoC 信号/对照/大小；不列出来会把整段
        // `signal=... control=...` 吞进前一个字段（arvo:62388 的 replay 就中过）。
        " signal=",
        " control=",
        " size=",
    ];
    let end = keys
        .iter()
        .filter_map(|candidate| rest.find(candidate))
        .min()
        .unwrap_or(rest.len());
    clean_marker_value(rest[..end].trim())
}

fn quoted_marker_value(rest: &str) -> Option<String> {
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut escaped = false;
    let mut value = String::new();
    for ch in rest[quote.len_utf8()..].chars() {
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn clean_marker_value(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('`').trim();
    let value = strip_balanced_outer_quotes(value)
        .trim()
        .trim_matches('`')
        .trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn strip_balanced_outer_quotes(value: &str) -> &str {
    if value.len() < 2 {
        return value;
    }
    let bytes = value.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn field_from_block(block: &[String], key: &str) -> Option<String> {
    let needle = format!("{key}:").to_ascii_lowercase();
    block.iter().find_map(|line| {
        let cleaned = clean_markdown_field_line(line);
        let lower = cleaned.to_ascii_lowercase();
        if lower.starts_with(&needle) {
            Some(
                cleaned[needle.len()..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            )
        } else {
            let bold_needle = format!("**{key}:**").to_ascii_lowercase();
            lower.starts_with(&bold_needle).then(|| {
                cleaned[bold_needle.len()..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string()
            })
        }
    })
}

fn clean_markdown_field_line(line: &str) -> &str {
    let trimmed = line.trim();
    let without_bullet = trimmed
        .strip_prefix("- ")
        .or_else(|| trimmed.strip_prefix("* "))
        .unwrap_or(trimmed);
    let without_number = without_bullet
        .trim_start_matches(|ch: char| ch.is_ascii_digit())
        .trim_start_matches(['.', ')'])
        .trim();
    if without_number.is_empty() {
        without_bullet
    } else {
        without_number
    }
}

fn is_finding_heading(line: &str) -> bool {
    finding_heading_title(line).is_some()
}

fn finding_heading_title(line: &str) -> Option<&str> {
    let cleaned = line
        .trim()
        .trim_start_matches('#')
        .trim()
        .trim_start_matches(|ch: char| ch == '-' || ch == '*' || ch.is_ascii_digit())
        .trim_start_matches(['.', ')'])
        .trim();
    let lower = cleaned.to_ascii_lowercase();
    if lower.starts_with("findings") || lower.starts_with("finding%") {
        return None;
    }
    if let Some((_, value)) = cleaned.split_once(':') {
        if lower.starts_with("finding:") && !value.trim().is_empty() {
            return Some(value.trim());
        }
    }
    let rest = lower.strip_prefix("finding")?.trim_start();
    if rest.is_empty() || rest.starts_with('s') {
        return None;
    }
    let title_start = cleaned
        .char_indices()
        .find_map(|(idx, ch)| {
            (idx > "finding".len()
                && (ch == '-' || ch == '—' || ch == ':' || ch.is_ascii_alphabetic()))
            .then_some((idx, ch))
        })
        .map(|(idx, ch)| {
            if ch == '-' || ch == '—' || ch == ':' {
                idx + ch.len_utf8()
            } else {
                idx
            }
        })
        .unwrap_or("finding".len());
    let title = cleaned[title_start..]
        .trim()
        .trim_start_matches(|ch: char| ch.is_ascii_digit())
        .trim_start_matches(['.', ')', '-', '—', ':'])
        .trim();
    if title.is_empty() {
        None
    } else {
        Some(title)
    }
}

fn infer_severity(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("critical") {
        "critical".to_string()
    } else if lower.contains("high") {
        "high".to_string()
    } else if lower.contains("medium") {
        "medium".to_string()
    } else if lower.contains("low") {
        "low".to_string()
    } else {
        "info".to_string()
    }
}

fn infer_category(text: &str) -> String {
    infer_coverage_category(text).unwrap_or_else(|| "api".to_string())
}

fn infer_coverage_category(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let category = if contains_any(
        &lower,
        &["authz", "idor", "permission", "privilege", "role"],
    ) {
        "authz"
    } else if contains_any(&lower, &["session", "httponly", "cookie", "localstorage"]) {
        "session"
    } else if contains_any(&lower, &["auth", "jwt", "session", "password", "login"]) {
        "auth"
    } else if contains_any(&lower, &["xss", "dom", "sanitize", "innerhtml"]) {
        "xss"
    } else if contains_any(&lower, &["xxe", "upload", "xml", "multipart", "parser"]) {
        "file_upload_xxe"
    } else if contains_any(&lower, &["traversal", "lfi", "../", "file read", "path"]) {
        "traversal_lfi"
    } else if contains_any(
        &lower,
        &["sql", "nosql", "template", "command", "injection", "rce"],
    ) {
        "injection"
    } else if contains_any(&lower, &["ssrf", "redirect", "url", "egress"]) {
        "ssrf_redirect"
    } else if contains_any(&lower, &["secret", "key", "config", "token"]) {
        "secrets_config"
    } else if contains_any(
        &lower,
        &[
            "directory listing",
            "exposed",
            "disclosure",
            "metrics",
            "swagger",
            "logs",
            "debug",
            "diagnostic",
            "docs",
        ],
    ) {
        "observability_leak"
    } else if contains_any(&lower, &["cors", "header", "tls", "hsts", "helmet"]) {
        "cors_headers_tls"
    } else if contains_any(&lower, &["rate", "brute", "limit"]) {
        "rate_limit"
    } else if contains_any(&lower, &["crypto", "md5", "hash", "cipher"]) {
        "crypto"
    } else if contains_any(
        &lower,
        &[
            "captcha",
            "security question",
            "security answer",
            "reset",
            "recovery",
            "anti automation",
            "anti-automation",
            "bot",
        ],
    ) {
        "anti_automation_bypass"
    } else if contains_any(
        &lower,
        &[
            "cart", "coupon", "checkout", "order", "price", "wallet", "payment", "negative",
            "entitlement", "subscription", "plan", "tier", "invariant",
        ],
    ) {
        "state_invariant_abuse"
    } else if contains_any(&lower, &["/api", "api/", "/rest", "rest/", "route"]) {
        "api"
    } else {
        return None;
    };
    Some(category.to_string())
}

fn coverage_signal_label(text: &str) -> String {
    first_line(text)
}

fn extract_payload_from_text(primary: &str, secondary: &str) -> String {
    let mut payload_lines = Vec::new();
    for line in format!("{primary}\n{secondary}").lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        if lower.starts_with("payload:")
            || lower.starts_with("exploit:")
            || lower.starts_with("poc:")
            || contains_any(
                &lower,
                &[
                    "curl ",
                    "http://",
                    "https://",
                    "union select",
                    " or 1=1",
                    "$where",
                    "<script",
                    "javascript:",
                    "../",
                    "<!doctype",
                    "{{",
                ],
            )
        {
            payload_lines.push(trimmed.to_string());
        }
        if payload_lines.len() >= 8 {
            break;
        }
    }
    truncate(&payload_lines.join("\n"), 900)
}

fn evidence_gate(code_path: &str, evidence: &str, confidence: &str) -> &'static str {
    let mut score = 0;
    if !evidence.trim().is_empty() {
        score += 1;
    }
    if !code_path.trim().is_empty() {
        score += 1;
    }
    if confidence.eq_ignore_ascii_case("high") {
        score += 1;
    }
    match score {
        0 | 1 => "signal",
        2 => "exploit+source",
        _ => "triad-ready",
    }
}

fn verification_weight(line: &str) -> usize {
    let lower = line.to_ascii_lowercase();
    [
        "exploit=",
        "root_cause=",
        "code_path=",
        "control=",
        "negative=",
        "validator=",
    ]
    .iter()
    .filter(|needle| lower.contains(**needle))
    .count()
    .max(1)
}

fn normalize_id(value: &str) -> String {
    let normalized: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut value: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        value.push_str("\n...[truncated]");
    }
    value
}

fn empty_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}

fn prefer_longer(existing: &str, incoming: &str, max_chars: usize) -> String {
    if incoming.trim().len() > existing.trim().len() {
        truncate(incoming, max_chars)
    } else {
        truncate(existing, max_chars)
    }
}

fn append_compact(existing: &str, incoming: &str, max_chars: usize) -> String {
    let incoming = incoming.trim();
    if incoming.is_empty() {
        return truncate(existing, max_chars);
    }
    if existing.contains(incoming) {
        return truncate(existing, max_chars);
    }
    if existing.trim().is_empty() {
        truncate(incoming, max_chars)
    } else {
        truncate(&format!("{}\n{}", existing.trim(), incoming), max_chars)
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

// --------------------------------------------------------------------------- //
// Structured PoC bundle helpers
//
// S5 的 POC% 行同时服务人类报告和 runner 的结构化 bundle。以下 helper 负责把
// agent 的自由写法收敛成 runner 能消费的值；任何派生都不要猜测，只做清洗。
// --------------------------------------------------------------------------- //

/// 清洗 marker 值：去引号/反引号，把 none/null/n/a 等占位值视为空。
fn clean_bundle_value(value: &str) -> String {
    let trimmed = value.trim().trim_matches('`').trim();
    let unquoted = strip_balanced_outer_quotes(trimmed).trim();
    let lower = unquoted.to_ascii_lowercase();
    if lower.is_empty()
        || matches!(
            lower.as_str(),
            "none" | "null" | "n/a" | "na" | "-" | "unknown" | "tbd"
        )
    {
        String::new()
    } else {
        unquoted.to_string()
    }
}

/// POC% 的 replay 是否是“容器化 fuzz 候选”形态（挂载 /tmp/poc）。
/// 只有这种形态才要求 file/role/observed_exit；web 任务的 curl replay 不受影响。
fn is_container_poc_replay(replay: &str) -> bool {
    replay.contains(":/tmp/poc") || replay.contains(" /tmp/poc")
}

/// 从 docker run 的 `-v <path>:/tmp/poc` 反推候选文件路径。
fn poc_file_from_replay(replay: &str) -> Option<String> {
    for token in replay.split_whitespace() {
        let value = token.trim_matches(|ch| ch == '\'' || ch == '"').to_string();
        let value = value
            .strip_prefix("--volume=")
            .or_else(|| value.strip_prefix("-v="))
            .unwrap_or(value.as_str());
        if let Some(idx) = value.find(":/tmp/poc") {
            let source = value[..idx].trim();
            if !source.is_empty() {
                return Some(source.to_string());
            }
        }
    }
    None
}

/// 把 agent 写的 role 收敛到 runner 的 VALID_ROLES 词表。
fn normalize_bundle_role(raw: &str) -> Option<String> {
    let value = clean_bundle_value(raw)
        .to_ascii_lowercase()
        .replace('_', "-");
    if value.is_empty() {
        return None;
    }
    let normalized = match value.as_str() {
        "final" | "final-candidate" | "finalcandidate" => "final_candidate",
        "candidate" | "poc" | "positive" | "positive-poc" => "candidate",
        "diagnostic" | "source-only" | "needs-poc" | "generated-not-verified" => "diagnostic",
        "negative-control" | "negative" | "control" => "negative_control",
        "scan-unknown" | "scan" => "scan_unknown",
        _ => return None,
    };
    Some(normalized.to_string())
}

/// 解析 observed_exit；接受 `1`、`exit=1`、`rc=1` 这类写法。
fn parse_observed_exit(value: &str) -> Option<i64> {
    let cleaned = clean_bundle_value(value);
    let mut token = String::new();
    for ch in cleaned.chars() {
        if ch.is_ascii_digit() {
            token.push(ch);
        } else if ch == '-' && token.is_empty() {
            token.push('-');
        } else if token.is_empty() {
            continue;
        } else {
            break;
        }
    }
    if token.is_empty() || token == "-" {
        return None;
    }
    token.parse::<i64>().ok()
}

/// 与 runner 的 verified 判定保持一致。
fn is_verified_verification(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "verified" | "vulnerable_runtime_confirmed" | "differential_verified"
    )
}

/// 解析候选文件：优先 `file=`，缺失时从 replay 的 /tmp/poc 挂载反推。
fn bundle_file_from_detail(detail: &str, replay: &str) -> String {
    let declared = detail_field(detail, "file");
    if !declared.is_empty() {
        return declared;
    }
    poc_file_from_replay(replay).unwrap_or_default()
}

/// 读取 detail 里 `key=value` 形式的一行（与 poc_bundle 的解析口径一致）。
fn detail_field(detail: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    detail
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|value| clean_bundle_value(value))
        .unwrap_or_default()
}
