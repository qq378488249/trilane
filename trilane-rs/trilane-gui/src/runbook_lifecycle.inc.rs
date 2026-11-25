fn compute_sha256(workspace: Option<&std::path::Path>, file: &str) -> Option<String> {
    if file.trim().is_empty() {
        return None;
    }
    let path = std::path::PathBuf::from(file);
    let resolved = if path.is_absolute() {
        path
    } else {
        workspace?.join(path)
    };
    if !resolved.is_file() {
        return None;
    }
    let bytes = std::fs::read(&resolved).ok()?;
    let digest = Sha256::digest(&bytes);
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

impl RunbookState {
    pub fn start_turn(&mut self, objective: &str, audit_mode: AuditMode) {
        let next_revision = self.revision.saturating_add(1);
        *self = Self::default();
        self.revision = next_revision;
        self.audit_mode = audit_mode;
        self.coverage = default_coverage(&self.audit_mode);
        self.status = RunbookStatus::Running;
        self.objective = objective.trim().to_string();
        self.activate_stage("stage0", "Admission check started");
        self.record_evidence(
            "stage0",
            "objective",
            "Agent objective",
            format!(
                "AUDIT_MODE% {}\n{}",
                self.audit_mode.as_marker(),
                truncate(objective, 500)
            ),
        );
    }

    pub fn set_turn_id(&mut self, turn_id: String) {
        self.status = RunbookStatus::Running;
        self.turn_id = Some(turn_id);
        self.touch();
    }

    pub fn complete(&mut self) {
        self.record_watchdog_if_needed();
        self.record_trilane_gate_if_needed();
        if let Some(reason) = self.trilane_s1_blocker() {
            self.record_evidence("stage1", "watchdog", "S1 surface ledger missing", reason);
            self.status = RunbookStatus::Error;
            self.current_stage = "stage1".to_string();
            self.mark_stage_blocked("stage1", "S1 ledger missing; rerun reconnaissance");
            self.touch();
            return;
        }
        if let Some(reason) = self.trilane_workflow_blocker() {
            // 先把 S5 的打包结果落下来，再标阻断：否则已经复现的 PoC 会随
            // final_findings=[] 一起消失，批次也就无法提交。
            self.finalize_stage5();
            self.record_evidence(
                "stage5",
                "workflow",
                "Workflow gate blocked before S5",
                reason,
            );
            self.status = RunbookStatus::Error;
            self.current_stage = "stage5".to_string();
            self.mark_stage_blocked("stage5", "Waiting for S5 verification/adjudication");
            self.touch();
            return;
        }
        self.finalize_stage5();
        self.status = RunbookStatus::Completed;
        self.mark_stage_done(&self.current_stage.clone());
        self.touch();
    }

    /// 最近一次阻断的真实原因，供 headless 写入 result.json.error。
    pub fn blocker_reason(&self) -> Option<String> {
        self.evidence
            .iter()
            .rev()
            .find(|evidence| {
                evidence.kind == "workflow"
                    && evidence.title.contains("Workflow gate blocked")
            })
            .map(|evidence| evidence.detail.clone())
            .or_else(|| {
                self.evidence
                    .iter()
                    .rev()
                    .find(|evidence| {
                        evidence.kind == "watchdog"
                            && evidence.title.contains("S1 surface ledger missing")
                    })
                    .map(|evidence| evidence.detail.clone())
            })
    }

    /// 结构化 PoC bundle：S5 打包结果，供控制器直接读取。
    /// 它只是候选清单，不替代官方 /submit-vul 的差分验证。
    ///
    /// `workspace` 用于把 `file=` 解析成真实文件并计算 sha256；拿不到时
    /// 保留声明值，runner 仍会按实际文件重算。
    pub fn poc_bundle(&self, workspace: Option<&std::path::Path>) -> serde_json::Value {
        let candidates = self
            .s5_bundle_source()
            .iter()
            .map(|finding| {
                let declared_verification = detail_field(&finding.detail, "verification");
                let verification = if declared_verification.is_empty() {
                    finding.evidence_state.clone()
                } else {
                    declared_verification
                };
                let replay = finding.payload.clone();
                let file = bundle_file_from_detail(&finding.detail, &replay);
                let sha256 = compute_sha256(workspace, &file)
                    .or_else(|| {
                        let declared = detail_field(&finding.detail, "sha256");
                        (!declared.is_empty()).then_some(declared)
                    })
                    .unwrap_or_default();
                let role = normalize_bundle_role(&detail_field(&finding.detail, "role"))
                    .unwrap_or_else(|| {
                        if is_verified_verification(&verification) && !file.is_empty() {
                            "candidate".to_string()
                        } else {
                            "diagnostic".to_string()
                        }
                    });
                serde_json::json!({
                    "file": file,
                    "role": role,
                    "sha256": sha256,
                    "family": detail_field(&finding.detail, "family"),
                    "finding": finding.candidate_id.clone().unwrap_or_default(),
                    "poc_id": finding.id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "code_path": finding.code_path,
                    "replay": replay,
                    "verification": verification,
                    "observed_exit": parse_observed_exit(
                        &detail_field(&finding.detail, "observed_exit"),
                    ),
                })
            })
            .collect::<Vec<_>>();

        // 不自动把第一个候选提升为 final_candidate：runner 对 final_candidate 的
        // no_crash 会提前收手，而引擎的顺序不一定等于最优顺序（arvo:58364 的
        // 第二个候选才是官方入口）。final_candidate 只由 agent 显式声明。
        serde_json::json!({
            "schema": 1,
            "generated": "trilane-s5",
            "candidates": candidates,
        })
    }

    /// S5 bundle 的最低 schema 检查：只对 `/tmp/poc` 形态的候选生效。
    ///
    /// 返回空表示可进入下一阶段；否则 workflow 会发起一次 repair，要求 agent
    /// 补齐字段。修复次数用尽后仍会放行，最终由 runner 的真实回放判定，
    /// 避免字段问题阻断整条流程。
    pub fn poc_bundle_schema_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        for finding in self.s5_bundle_source() {
            let replay = finding.payload.trim();
            if !is_container_poc_replay(replay) {
                continue;
            }
            let file = bundle_file_from_detail(&finding.detail, replay);
            let verification = {
                let declared = detail_field(&finding.detail, "verification");
                if declared.is_empty() {
                    finding.evidence_state.clone()
                } else {
                    declared
                }
            };
            if file.is_empty() {
                issues.push(format!(
                    "{}: missing file= (or -v <path>:/tmp/poc in replay)",
                    finding.id
                ));
            }
            let role = detail_field(&finding.detail, "role");
            if role.is_empty() {
                issues.push(format!("{}: missing role=", finding.id));
            }
            if is_verified_verification(&verification)
                && parse_observed_exit(&detail_field(&finding.detail, "observed_exit")).is_none()
            {
                issues.push(format!(
                    "{}: missing observed_exit= for verified candidate",
                    finding.id
                ));
            }
        }
        issues
    }

    fn s5_bundle_source(&self) -> Vec<&RunbookFinding> {
        if !self.stage5_poc_entries.is_empty() {
            self.stage5_poc_entries.iter().collect()
        } else {
            self.findings
                .iter()
                .filter(|finding| finding.stage == "stage5")
                .collect()
        }
    }

    pub fn final_report_markdown(&self) -> String {
        let findings = if self.status == RunbookStatus::Error {
            self.final_findings.clone()
        } else if self.final_findings.is_empty() {
            crate::runbook_finalize::adjudicate_findings(&self.findings, &self.claims).0
        } else {
            self.final_findings.clone()
        };
        let verified = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.verification_status.as_str(),
                    "publishable" | "weaponized" | "verified"
                )
            })
            .count();
        let generated_not_verified = findings
            .iter()
            .filter(|finding| finding.verification_status == "generated-not-verified")
            .count();
        let needs_poc = findings
            .iter()
            .filter(|finding| {
                finding.payload.trim().is_empty()
                    || matches!(
                        finding.verification_status.as_str(),
                        "source-backed" | "runtime-signal" | "needs-poc"
                    )
            })
            .count();
        let mut report = String::new();
        report.push_str("# TriLane PoC Bundle\n\n");
        report.push_str(&format!(
            "- Objective: {}\n- Audit mode: {}\n- Workflow status: {:?}\n- Turn: {}\n- Root claims: {}\n- Publishable claims: {}\n- Raw findings: {}\n- PoC entries: {}\n- Verified PoCs: {}\n- Generated-not-verified PoCs: {}\n- Needs PoC: {}\n- Duplicates collapsed: {}\n\n",
            report_objective(&self.objective),
            self.audit_mode.as_marker(),
            self.status,
            self.turn_id.as_deref().unwrap_or("unknown"),
            self.claim_summary.root_claims,
            self.claim_summary.publishable,
            self.dedupe_summary.raw_findings.max(self.findings.len()),
            findings.len(),
            verified,
            generated_not_verified,
            needs_poc,
            self.dedupe_summary.duplicates,
        ));
        report.push_str("## PoC Entries\n\n");
        for finding in &findings {
            report.push_str(&format!("### {} - {}\n\n", finding.id, finding.title));
            report.push_str(&format!(
                "- Severity: {}\n- Verification: {}\n- Confidence: {}\n- Target/location: {}\n- Code path: {}\n- Source claim/finding: {}\n- Duplicates collapsed: {}\n\n",
                finding.severity.to_uppercase(),
                finding.verification_status,
                finding.confidence,
                empty_dash(&finding.location),
                empty_dash(&finding.code_path),
                finding.candidate_id.as_deref().unwrap_or("-"),
                finding.duplicates.len(),
            ));
            report.push_str("PoC metadata:\n\n");
            report.push_str("```text\n");
            report.push_str(&finding.detail);
            report.push_str("\n```\n\n");
            if !finding.payload.trim().is_empty() {
                report.push_str("Replay:\n\n");
                report.push_str("```text\n");
                report.push_str(&finding.payload);
                report.push_str("\n```\n\n");
            } else {
                report.push_str("Replay: `needs-poc`\n\n");
            }
        }
        report
    }

    pub fn fail(&mut self, message: &str) {
        self.status = RunbookStatus::Error;
        self.record_evidence(
            &self.current_stage.clone(),
            "error",
            "Agent error",
            truncate(message, 500),
        );
        self.touch();
    }

    pub fn stop_turn(&mut self, reason: &str) {
        self.status = RunbookStatus::Error;
        let stage_id = self.current_stage.clone();
        self.mark_stage_blocked(&stage_id, reason);
        for lane in self.lanes.iter_mut().filter(|lane| {
            lane.stage == stage_id && matches!(lane.status.as_str(), "queued" | "running" | "retrying")
        }) {
            lane.status = "failed".to_string();
            lane.summary = reason.to_string();
            lane.updated_at = now();
        }
        self.record_evidence(&stage_id, "stop", "Agent stopped", truncate(reason, 500));
        self.touch();
    }

    pub fn record_workflow_phase(&mut self, stage_id: &str, summary: &str) {
        self.activate_stage(stage_id, summary);
        self.record_evidence(
            stage_id,
            "workflow",
            summary,
            format!("Backend workflow entered {stage_id}: {summary}"),
        );
    }

    pub fn record_subagent_lane(&mut self, update: RunbookLaneUpdate<'_>) {
        let RunbookLaneUpdate {
            stage,
            lane_id,
            status,
            claim_count,
            candidate_count,
            thread_id,
            summary,
        } = update;
        let lane_id = lane_id.trim();
        if lane_id.is_empty() {
            return;
        }
        let normalized_status = normalize_lane_status(status);
        let position = self.lanes.iter().position(|lane| lane.lane_id == lane_id);
        let mut lane = position
            .and_then(|index| self.lanes.get(index).cloned())
            .unwrap_or_else(|| RunbookLane {
                lane_id: lane_id.to_string(),
                stage: stage.to_string(),
                status: "spawned".to_string(),
                claim_count: 0,
                candidate_count: 0,
                thread_id: String::new(),
                summary: String::new(),
                updated_at: now(),
        });
        lane.stage = stage.to_string();
        lane.status = normalized_status.to_string();
        if let Some(count) = claim_count {
            lane.claim_count = count;
        }
        if let Some(count) = candidate_count {
            lane.candidate_count = count;
        }
        match thread_id.map(str::trim) {
            Some(thread_id) if !thread_id.is_empty() => {
                lane.thread_id = thread_id.to_string();
            }
            Some(_) | None => {}
        }
        if !summary.trim().is_empty() {
            lane.summary = truncate(summary.trim(), 300);
        }
        lane.updated_at = now();
        if let Some(index) = position {
            self.lanes[index] = lane;
        } else {
            self.lanes.push(lane);
        }
        self.record_evidence(
            stage,
            "subagent",
            format!("S2 lane {lane_id} {normalized_status}"),
            format!(
                "SUBAGENT% lane={lane_id} status={normalized_status} claims={} candidates={} thread_id={} note={}",
                claim_count.unwrap_or(0),
                candidate_count.unwrap_or(0),
                thread_id.unwrap_or(""),
                truncate(summary, 300)
            ),
        );
        self.touch();
    }

    pub fn s2_required_lanes_complete(&self) -> bool {
        self.s2_missing_lanes().is_empty()
    }

    pub fn s2_quick_hits_finished(&self) -> bool {
        self.lanes.iter().any(|lane| {
            lane.lane_id == "quick_hits_engine" && matches!(lane.status.as_str(), "done" | "failed")
        })
    }

    pub fn s2_missing_lanes(&self) -> Vec<String> {
        required_s2_lanes()
            .iter()
            .filter(|lane_id| {
                !self
                    .lanes
                    .iter()
                    .any(|lane| lane.lane_id == **lane_id && s2_lane_complete(lane))
            })
            .map(|lane_id| (*lane_id).to_string())
            .collect()
    }

    pub fn s2_completed_lane_count(&self) -> usize {
        required_s2_lanes()
            .iter()
            .filter(|lane_id| {
                self.lanes
                    .iter()
                    .any(|lane| lane.lane_id == **lane_id && s2_lane_complete(lane))
            })
            .count()
    }

    pub fn record_reasoning(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let stage = self.ingest_stage(classify_stage(text, None));
        self.prepare_s5_final_revision_ingest(&stage, text);
        self.activate_stage_from_signal(&stage);
        self.record_evidence(&stage, "trace", first_line(text), truncate(text, 900));
        self.record_runbook_markers(text);
        self.extract_ledger_from_text(&stage, text);
    }

    pub fn record_agent_message(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let stage = self.ingest_stage(classify_stage(text, None));
        self.prepare_s5_final_revision_ingest(&stage, text);
        self.activate_stage_from_signal(&stage);
        if looks_like_report(text) {
            self.activate_stage_from_signal("stage3");
        }
        self.record_evidence(&stage, "agent", first_line(text), truncate(text, 1200));
        self.record_runbook_markers(text);
        self.extract_ledger_from_text(&stage, text);
        if looks_like_report(text) {
            self.record_watchdog_if_needed();
        }
    }

    pub fn record_command(
        &mut self,
        command: &str,
        output: Option<&str>,
        status: &str,
        exit_code: Option<i32>,
    ) {
        let stage = self.ingest_stage(classify_stage(command, output));
        self.activate_stage_from_signal(&stage);
        let mut detail = format!("$ {command}\nstatus={status}");
        if let Some(code) = exit_code {
            detail.push_str(&format!(" exit={code}"));
        }
        if let Some(output) = output {
            if !output.trim().is_empty() {
                detail.push_str("\n--- output ---\n");
                detail.push_str(&truncate(output, 1200));
            }
        }
        self.record_evidence(&stage, "command", command_title(command), detail);
        let inferred_finding = (stage != "stage5")
            .then(|| infer_finding_from_command(command, output.unwrap_or_default()))
            .flatten();
        if let Some(finding) = inferred_finding {
            let candidate_id =
                self.upsert_candidate(&stage, "auto", finding.1, command_title(command));
            self.record_probe(&candidate_id, &stage, "machine signal from command output");
            self.add_finding(RunbookFindingInput {
                stage: &stage,
                candidate_id: Some(candidate_id),
                severity: finding.0,
                title: finding.1,
                code_path: "",
                confidence: "medium",
                evidence_state: "exploit proof",
                detail: finding.2,
                payload: extract_payload_from_text(command, output.unwrap_or_default()),
            });
        }
    }

    fn ingest_stage(&self, classified_stage: &str) -> String {
        if self.status != RunbookStatus::Idle {
            self.current_stage.clone()
        } else {
            classified_stage.to_string()
        }
    }

    fn prepare_s5_final_revision_ingest(&mut self, _stage: &str, text: &str) {
        if !text
            .to_ascii_lowercase()
            .contains("runbook% s5 final revision")
        {
            return;
        }
        self.findings.retain(|finding| finding.stage != "stage5");
        self.final_findings.clear();
        self.dedupe_summary = RunbookDedupeSummary::default();
    }

    fn activate_stage_from_signal(&mut self, _stage_id: &str) {
        // Workflow prompts, lane joins, and explicit backend phase transitions own the
        // visible stage state. Agent text is still ingested as evidence, but it cannot
        // make the Scan UI jump ahead of the scheduler.
    }

    fn activate_stage(&mut self, stage_id: &str, summary: &str) {
        let target_idx = stage_index(stage_id).unwrap_or(0);
        let current_idx = stage_index(&self.current_stage).unwrap_or(0);
        if self.status != RunbookStatus::Idle && target_idx < current_idx {
            if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
                stage.summary = summary.to_string();
                stage.updated_at = now();
            }
            self.touch();
            return;
        }
        for (idx, stage) in self.stages.iter_mut().enumerate() {
            stage.status = if idx < target_idx {
                StageStatus::Done
            } else if idx == target_idx {
                StageStatus::Active
            } else {
                StageStatus::Pending
            };
        }
        self.current_stage = stage_id.to_string();
        if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
            stage.summary = summary.to_string();
            stage.updated_at = now();
        }
        self.status = RunbookStatus::Running;
        self.touch();
    }

    fn mark_stage_done(&mut self, stage_id: &str) {
        if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
            stage.status = StageStatus::Done;
            stage.updated_at = now();
        }
    }

    fn mark_stage_blocked(&mut self, stage_id: &str, summary: &str) {
        let target_idx = stage_index(stage_id).unwrap_or(0);
        for (idx, stage) in self.stages.iter_mut().enumerate() {
            stage.status = if idx < target_idx {
                StageStatus::Done
            } else if idx == target_idx {
                StageStatus::Blocked
            } else {
                StageStatus::Pending
            };
        }
        if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
            stage.summary = summary.to_string();
            stage.updated_at = now();
        }
    }

    fn record_evidence(
        &mut self,
        stage: &str,
        kind: &str,
        title: impl Into<String>,
        detail: String,
    ) {
        self.evidence_total = self.evidence_total.saturating_add(1);
        let evidence = RunbookEvidence {
            id: format!("ev-{}", self.evidence_total),
            stage: stage.to_string(),
            kind: kind.to_string(),
            title: truncate(&title.into(), 120),
            detail,
            timestamp: now(),
        };
        self.evidence.push(evidence);
        if self.evidence.len() > MAX_EVIDENCE {
            self.evidence.remove(0);
        }
        self.mark_coverage_from_signal(&format!(
            "{}\n{}\n{}",
            kind,
            self.evidence
                .last()
                .map(|evidence| evidence.title.as_str())
                .unwrap_or_default(),
            self.evidence
                .last()
                .map(|evidence| evidence.detail.as_str())
                .unwrap_or_default()
        ));
        self.touch();
    }

    fn record_runbook_markers(&mut self, text: &str) {
        for line in text.lines() {
            let line = normalize_marker_line(line);
            let Some(stage) = runbook_marker_stage(&line) else {
                continue;
            };
            self.record_evidence(stage, "runbook", first_line(&line), truncate(&line, 300));
        }
    }

}

fn report_objective(objective: &str) -> String {
    let head = objective
        .split("RESUME_RUN_CONTEXT%")
        .next()
        .unwrap_or(objective)
        .split("RUNBOOK_CONTEXT%")
        .next()
        .unwrap_or(objective);
    let cleaned = head
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("/.trilane/runs/")
                && !lower.contains("stage0/")
                && !lower.contains("stage1/")
                && !lower.contains("stage2/")
                && !lower.contains("stage3/")
                && !lower.contains("stage4/")
                && !lower.contains("stage5/")
                && !lower.starts_with("original_objective%")
                && !lower.starts_with("resume_run_context%")
        })
        .collect::<Vec<_>>()
        .join(" ");
    truncate(&cleaned, 320)
}
