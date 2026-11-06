// Headless runner: drives one TriLane workflow without creating any window.
//
//   trilane-gui --headless --objective-file <md> --out-dir <dir>
//               [--cwd <dir>] [--audit-mode safe|lab] [--headless-timeout-sec <n>]
//
// Writes <out-dir>/result.json and <out-dir>/report.md, then exits:
//   0 runbook completed / 1 runbook error / 2 startup failure / 3 timeout

#[derive(Clone, Debug)]
struct HeadlessOptions {
    objective: String,
    out_dir: std::path::PathBuf,
    audit_mode: String,
    cwd: Option<String>,
    timeout_sec: u64,
}

fn headless_request() -> Result<Option<HeadlessOptions>, String> {
    let args = std::env::args().collect::<Vec<_>>();
    if !args.iter().any(|arg| arg == "--headless") {
        return Ok(None);
    }
    let objective_file = cli_arg_value(&args, "--objective-file")
        .ok_or_else(|| "--headless requires --objective-file <path>".to_string())?;
    let objective = std::fs::read_to_string(&objective_file)
        .map_err(|error| format!("cannot read objective file {objective_file}: {error}"))?;
    if objective.trim().is_empty() {
        return Err(format!("objective file {objective_file} is empty"));
    }
    let out_dir = cli_arg_value(&args, "--out-dir")
        .ok_or_else(|| "--headless requires --out-dir <path>".to_string())?;
    let audit_mode = cli_arg_value(&args, "--audit-mode").unwrap_or_else(|| "lab".to_string());
    if audit_mode != "safe" && audit_mode != "lab" {
        return Err(format!(
            "invalid --audit-mode {audit_mode:?}; expected \"safe\" or \"lab\""
        ));
    }
    let timeout_sec = cli_arg_value(&args, "--headless-timeout-sec")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(7200);
    Ok(Some(HeadlessOptions {
        objective,
        out_dir: std::path::PathBuf::from(out_dir),
        audit_mode,
        cwd: cli_arg_value(&args, "--cwd"),
        timeout_sec,
    }))
}

async fn run_headless(app: AppHandle, options: HeadlessOptions) {
    // Give the in-process app-server and state store a beat to settle, same as the
    // GUI startup-resume path does.
    tokio::time::sleep(Duration::from_millis(800)).await;

    let mode = options.audit_mode.clone();
    let state = app.state::<AppState>();
    if let Err(error) =
        start_agent(state, app.clone(), None, options.cwd.clone(), Some(mode.clone())).await
    {
        warn!("headless: start_agent failed: {error}");
        write_headless_result(&options, "agent_start_failed", None, &[], Some(error)).await;
        app.exit(2);
        return;
    }
    let state = app.state::<AppState>();
    if let Err(error) = send_message(app.clone(), state, options.objective.clone(), Some(mode)).await
    {
        warn!("headless: send_message failed: {error}");
        write_headless_result(&options, "send_failed", None, &[], Some(error)).await;
        app.exit(2);
        return;
    }
    info!(
        "headless: workflow started; polling runbook (timeout {}s)",
        options.timeout_sec
    );

    let deadline = Instant::now() + Duration::from_secs(options.timeout_sec);
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let state = app.state::<AppState>();
        let runbook = current_runbook_snapshot(&state).await;
        let outcome = match runbook.status {
            runbook::RunbookStatus::Completed => Some(("completed", 0)),
            runbook::RunbookStatus::Error => Some(("error", 1)),
            _ => None,
        };
        if let Some((status, code)) = outcome {
            let findings = get_findings(app.state::<AppState>()).await.unwrap_or_default();
            write_headless_result(&options, status, Some(&runbook), &findings, None).await;
            app.exit(code);
            return;
        }
        if Instant::now() >= deadline {
            let findings = get_findings(app.state::<AppState>()).await.unwrap_or_default();
            write_headless_result(
                &options,
                "timeout",
                Some(&runbook),
                &findings,
                Some(format!(
                    "workflow did not finish within {}s",
                    options.timeout_sec
                )),
            )
            .await;
            app.exit(3);
            return;
        }
    }
}

async fn write_headless_result(
    options: &HeadlessOptions,
    status: &str,
    runbook: Option<&runbook::RunbookState>,
    findings: &[Finding],
    error: Option<String>,
) {
    let mut report_path: Option<String> = None;
    let mut stages = serde_json::Value::Null;
    if let Some(runbook) = runbook {
        let markdown = runbook.final_report_markdown();
        if !markdown.trim().is_empty() {
            let path = options.out_dir.join("report.md");
            if std::fs::write(&path, markdown).is_ok() {
                report_path = Some(path.display().to_string());
            }
        }
        stages = serde_json::to_value(&runbook.stages).unwrap_or(serde_json::Value::Null);
    }
    let payload = serde_json::json!({
        "status": status,
        "audit_mode": options.audit_mode,
        "workspace": options.cwd,
        "out_dir": options.out_dir.display().to_string(),
        "report_path": report_path,
        "stages": stages,
        "findings": findings,
        "error": error,
        "finished_at": chrono::Local::now().to_rfc3339(),
    });
    let _ = std::fs::create_dir_all(&options.out_dir);
    let path = options.out_dir.join("result.json");
    match serde_json::to_vec_pretty(&payload) {
        Ok(bytes) => {
            if let Err(write_error) = std::fs::write(&path, bytes) {
                eprintln!(
                    "trilane headless: failed to write {}: {write_error}",
                    path.display()
                );
            }
        }
        Err(serialize_error) => {
            eprintln!("trilane headless: failed to serialize result: {serialize_error}");
        }
    }
}
