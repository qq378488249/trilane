    fn test_lane(id: &str) -> WorkflowLaneSpec {
        WorkflowLaneSpec {
            lane_id: id.to_string(),
            title: id.to_string(),
            prompt: "audit this lane".to_string(),
        }
    }

    fn turn_error(
        message: &str,
        info: Option<codex_app_server_protocol::CodexErrorInfo>,
    ) -> codex_app_server_protocol::TurnError {
        codex_app_server_protocol::TurnError {
            message: message.to_string(),
            codex_error_info: info,
            additional_details: None,
        }
    }

    #[test]
    fn retryable_lane_errors_cover_provider_failures() {
        use codex_app_server_protocol::CodexErrorInfo;

        assert!(should_retry_lane_error(&turn_error(
            "exceeded retry limit, last status: 429 Too Many Requests",
            Some(CodexErrorInfo::ResponseTooManyFailedAttempts {
                http_status_code: Some(429),
            }),
        )));
        assert!(should_retry_lane_error(&turn_error(
            "unexpected status 503 Service Unavailable",
            None,
        )));
        assert!(should_retry_lane_error(&turn_error(
            "unauthorized",
            Some(CodexErrorInfo::Unauthorized),
        )));
        assert!(!should_retry_lane_error(&turn_error(
            "turn was interrupted by the user",
            None,
        )));
        assert!(!should_retry_lane_error(&turn_error(
            "active turn cannot accept steering",
            Some(CodexErrorInfo::ActiveTurnNotSteerable {
                turn_kind: codex_app_server_protocol::NonSteerableTurnKind::Review,
            }),
        )));
    }

    #[test]
    fn lane_retry_delay_grows_then_stops_at_cap() {
        assert_eq!(workflow_lane_retry_delay(1), Duration::from_secs(20));
        assert_eq!(workflow_lane_retry_delay(2), Duration::from_secs(30));
        assert_eq!(workflow_lane_retry_delay(8), Duration::from_secs(30));
    }

    #[test]
    fn streaming_delta_parser_keeps_s2_lane_markers() {
        assert!(is_visual_runbook_delta_marker(
            "CLAIM% id=ID-CAND-01 category=auth target=routes/login.ts"
        ));
        assert!(is_visual_runbook_delta_marker(
            "SUBAGENT% lane=identity_engine status=done claims=1 candidates=1"
        ));
        assert!(is_visual_runbook_delta_marker(
            "`DUPLICATE% id=QH-DUP-01 merge_into=CONFIG-CAND-01`"
        ));
        assert!(!is_visual_runbook_delta_marker(
            "This is ordinary reasoning prose without a marker."
        ));
    }

    #[test]
    fn lane_batch_tracks_idle_running_lanes() {
        let batch = WorkflowLaneBatch {
            phase_id: "s2_parallel_semantic_audit".to_string(),
            stage_id: "stage2".to_string(),
            title: "S2 concurrent audit".to_string(),
            lanes: vec![test_lane("identity_engine"), test_lane("config_engine")],
            is_repair: false,
        };
        let mut active = ActiveLaneBatch::new(&batch, /*max_concurrency*/ 2);
        active.lanes[0].mark_starting();
        active.lanes[0].thread_id = "thread-a".to_string();
        active.lanes[0].turn_id = Some("turn-a".to_string());
        active.lanes[0].last_activity_at = Some(Instant::now() - Duration::from_secs(700));
        active.lanes[1].mark_starting();
        active.lanes[1].thread_id = "thread-b".to_string();
        active.lanes[1].turn_id = Some("turn-b".to_string());
        active.mark_activity("thread-b", "turn-b");

        assert_eq!(
            active.idle_running_lane_indices(Instant::now(), Duration::from_secs(600)),
            vec![0]
        );
        assert_eq!(active.lane_index_by_event("wrong-thread", "turn-b"), Some(1));
    }

    #[test]
    fn lane_batch_tracks_retry_without_completing_batch() {
        let batch = WorkflowLaneBatch {
            phase_id: "s2_parallel_semantic_audit".to_string(),
            stage_id: "stage2".to_string(),
            title: "S2 concurrent 6-lane semantic audit".to_string(),
            lanes: vec![test_lane("auth"), test_lane("business")],
            is_repair: false,
        };
        let mut active = ActiveLaneBatch::new(&batch, /*max_concurrency*/ 1);
        active.lanes[0].mark_starting();
        active.lanes[0].thread_id = "thread-a".to_string();
        active.lanes[0].attempts = 1;

        let delay = active.retry_lane(0, "429 Too Many Requests");

        assert!(delay > Duration::from_secs(0));
        assert_eq!(active.lanes[0].status, ActiveLaneStatus::Queued);
        assert!(!active.all_complete());
        assert_eq!(active.running_count(), 0);
    }

    #[test]
    fn provider_ids_are_safe_toml_table_keys() {
        assert!(valid_provider_id("company-deepseek"));
        assert!(valid_provider_id("gateway_2"));
        assert!(!valid_provider_id("Company deepseek"));
        assert!(!valid_provider_id("provider.name"));
    }
