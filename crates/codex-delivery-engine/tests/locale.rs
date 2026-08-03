use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use codex_delivery_engine::contract::normalize_locale;
use codex_delivery_engine::{
    run_locale_task, LocaleContract, LocaleInitError, LocaleInitializer, LocaleMode,
    LocaleTaskState,
};

const NOW: i64 = 1_900_000_000;

#[derive(Default)]
struct RecordingInitializer {
    calls: usize,
    relay_seen: bool,
    result: Option<LocaleInitError>,
}

#[test]
fn common_windows_and_macos_locale_variants_normalize_identically() {
    let cases = [
        ("zh_cn", "zh-CN"),
        ("ZH-hans-cn", "zh-Hans-CN"),
        ("yue_hant_hk", "yue-Hant-HK"),
        ("en-us", "en-US"),
        ("pt_BR", "pt-BR"),
        ("es-419", "es-419"),
    ];
    for (raw, expected) in cases {
        assert_eq!(normalize_locale(raw).as_deref(), Some(expected));
    }
    for invalid in ["", "z", "zh--CN", "zh-!", "zh-123456789"] {
        assert!(normalize_locale(invalid).is_none());
    }
}

impl LocaleInitializer for RecordingInitializer {
    fn initialize(
        &mut self,
        _contract: &LocaleContract,
        relay_bundle: Option<&[u8]>,
    ) -> Result<(), LocaleInitError> {
        self.calls += 1;
        self.relay_seen = relay_bundle.is_some();
        self.result.take().map_or(Ok(()), Err)
    }
}

fn contract(mode: LocaleMode, required: bool) -> LocaleContract {
    LocaleContract {
        schema_version: 1,
        target_locale: "zh-CN".to_string(),
        required,
        mode,
        issued_at_unix: NOW - 60,
        expires_at_unix: NOW + 60,
    }
}

fn relay(target: &str, issued: i64, expires: i64) -> String {
    STANDARD.encode(
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "target_locale": target,
            "issued_at_unix": issued,
            "expires_at_unix": expires,
            "payload": { "opaque": "short-lived" }
        }))
        .unwrap(),
    )
}

#[test]
fn native_initialization_is_independent_and_never_requests_app_or_config_rollback() {
    let mut initializer = RecordingInitializer::default();
    let report = run_locale_task(
        &contract(LocaleMode::NativeSystem, true),
        "zh_CN",
        None,
        NOW,
        &mut initializer,
    );

    assert_eq!(report.state, LocaleTaskState::Succeeded);
    assert_eq!(report.attempts, 1);
    assert_eq!(initializer.calls, 1);
    assert!(!initializer.relay_seen);
    assert!(!report.config_rollback_required);
    assert!(!report.app_rollback_required);
}

#[test]
fn optional_locale_is_skipped_without_invoking_initializer() {
    let mut initializer = RecordingInitializer::default();
    let report = run_locale_task(
        &contract(LocaleMode::NativeSystem, false),
        "zh-CN",
        None,
        NOW,
        &mut initializer,
    );

    assert_eq!(report.state, LocaleTaskState::Skipped);
    assert_eq!(report.attempts, 0);
    assert_eq!(initializer.calls, 0);
}

#[test]
fn valid_short_lived_relay_is_decoded_only_for_initializer() {
    let mut initializer = RecordingInitializer::default();
    let encoded = relay("zh-cn", NOW - 30, NOW + 30);
    let report = run_locale_task(
        &contract(LocaleMode::ShortLivedRelay, true),
        "zh-CN",
        Some(&encoded),
        NOW,
        &mut initializer,
    );

    assert_eq!(report.state, LocaleTaskState::Succeeded);
    assert!(initializer.relay_seen);
    assert_eq!(report.error_code, None);
}

#[test]
fn malformed_or_wrong_target_relay_fails_closed_before_initializer() {
    for encoded in [
        "not-base64".to_string(),
        STANDARD.encode(b"not-json"),
        relay("en-US", NOW - 30, NOW + 30),
        relay("zh-CN", NOW - 10_000, NOW - 9_500),
    ] {
        let mut initializer = RecordingInitializer::default();
        let report = run_locale_task(
            &contract(LocaleMode::ShortLivedRelay, true),
            "zh-CN",
            Some(&encoded),
            NOW,
            &mut initializer,
        );
        assert_eq!(report.state, LocaleTaskState::FailedPermanent);
        assert_eq!(initializer.calls, 0);
        assert!(!report.config_rollback_required);
        assert!(!report.app_rollback_required);
    }
}

#[test]
fn locale_contract_mismatch_fails_closed() {
    let mut initializer = RecordingInitializer::default();
    let report = run_locale_task(
        &contract(LocaleMode::NativeSystem, true),
        "en-US",
        None,
        NOW,
        &mut initializer,
    );

    assert_eq!(report.state, LocaleTaskState::FailedPermanent);
    assert_eq!(
        report.error_code.as_deref(),
        Some("locale-contract-mismatch")
    );
    assert_eq!(initializer.calls, 0);
}

#[test]
fn initializer_classifies_retryable_failure_without_rolling_back_other_domains() {
    let mut initializer = RecordingInitializer {
        result: Some(LocaleInitError {
            code: "locale-service-timeout".to_string(),
            retryable: true,
        }),
        ..Default::default()
    };
    let report = run_locale_task(
        &contract(LocaleMode::NativeSystem, true),
        "zh-CN",
        None,
        NOW,
        &mut initializer,
    );

    assert_eq!(report.state, LocaleTaskState::FailedRetryable);
    assert_eq!(report.error_code.as_deref(), Some("locale-service-timeout"));
    assert!(!report.config_rollback_required);
    assert!(!report.app_rollback_required);
}
