import io

import pandas as pd

from dashboard.app import classify_outcome, make_cases, safe_export_csv, sort_cases, stable_case_id


def event(time, alert_type="محاولة دخول فاشلة", outcome="failure", severity="منخفضة",
          source="203.0.113.10", target="vpn.local", account="analyst", rule="login_rule"):
    return {
        "alert_time": pd.Timestamp(time, tz="Asia/Riyadh"),
        "alert_type": alert_type,
        "source_ip": source,
        "target": target,
        "target_account": account,
        "severity": severity,
        "detection_rule": rule,
        "event_outcome": outcome,
    }


def cases_for(rows, dataset_id="file-a"):
    return make_cases(pd.DataFrame(rows), "upload", dataset_id)[0]


def test_case_ids_are_stable_for_same_file_and_isolated_between_files():
    rows = [event("2026-11-07 09:00")]
    first = cases_for(rows, "same-file").iloc[0]["case_id"]
    repeated = cases_for(rows, "same-file").iloc[0]["case_id"]
    different = cases_for(rows, "different-file").iloc[0]["case_id"]
    assert first == repeated
    assert first != different


def test_urgent_always_sorts_before_high_regardless_of_event_count():
    cases = pd.DataFrame([
        {"case_id": "high", "priority_level": 3, "event_count": 103, "last_time": pd.Timestamp("2026-01-02")},
        {"case_id": "urgent", "priority_level": 4, "event_count": 1, "last_time": pd.Timestamp("2026-01-01")},
    ])
    assert sort_cases(cases).iloc[0]["case_id"] == "urgent"


def test_window_duration_is_measured_from_first_event():
    cases = cases_for([
        event("2026-11-07 09:00"),
        event("2026-11-07 09:04"),
        event("2026-11-07 09:08"),
    ])
    assert list(cases["event_count"].sort_values()) == [1, 2]


def test_success_only_adds_context_after_failure_and_types_are_merged():
    linked = cases_for([
        event("2026-11-07 09:00", "محاولة دخول فاشلة", "failure"),
        event("2026-11-07 09:01", "تسجيل دخول ناجح", "success"),
    ]).iloc[0]
    success_only = cases_for([
        event("2026-11-07 09:00", "تسجيل دخول ناجح", "success"),
    ]).iloc[0]
    assert linked["event_count"] == 2
    assert linked["priority_level"] == success_only["priority_level"] + 1
    assert "نجاح دخول بعد فشل" in linked["reason"]


def test_case_displays_highest_severity_but_evidence_keeps_each_value():
    rows = [
        event("2026-11-07 09:00", severity="منخفضة"),
        event("2026-11-07 09:01", severity="حرجة"),
    ]
    cases, evidence = make_cases(pd.DataFrame(rows), "upload", "mixed-severity")
    case = cases.iloc[0]
    assert case["severity"] == "حرجة"
    assert set(evidence[case["case_id"]]["severity"]) == {"منخفضة", "حرجة"}


def test_csv_export_neutralizes_spreadsheet_formulas():
    row = {
        "case_id": "csv-safe", "first_time": pd.NaT, "last_time": pd.NaT,
        "alert_type": "=HYPERLINK(\"https://evil.example\")", "source_ip": "+cmd",
        "target": "  @SUM(1+1)", "target_account": "normal", "severity": "عالية",
        "priority": "عالية", "reason": "-formula", "event_count": 1,
        "detection_rule": "rule", "status": "جديدة", "verdict": "غير محددة",
        "notes": "=1+1",
    }
    exported = pd.read_csv(io.BytesIO(safe_export_csv(pd.DataFrame([row]))))
    assert exported.loc[0, "notes"].startswith("'=")
    assert exported.loc[0, "alert_type"].startswith("'=")
    assert exported.loc[0, "source_ip"].startswith("'+")
    assert exported.loc[0, "target"].startswith("'")
    assert exported.loc[0, "reason"].startswith("'-")


def test_non_login_alerts_are_not_merged_or_given_login_context():
    cases = cases_for([
        event("2026-11-07 09:00", "فشل استعلام DNS", "failure", rule="dns_rule"),
        event("2026-11-07 09:01", "نجاح رفع ملف", "success", rule="upload_rule"),
    ])
    assert len(cases) == 2
    assert not cases["reason"].str.contains("نجاح دخول بعد فشل").any()


def test_explicit_outcome_wins_over_misleading_description():
    row = pd.Series({"alert_type": "Unsuccessful login", "event_outcome": "failure"})
    assert classify_outcome(row) == "failure"


def test_login_success_is_not_linked_without_a_known_account():
    case = cases_for([
        event("2026-11-07 09:00", "محاولة دخول فاشلة", "failure", account=""),
        event("2026-11-07 09:01", "تسجيل دخول ناجح", "success", account=""),
    ]).iloc[0]
    assert case["priority_level"] == 1
    assert "نجاح دخول بعد فشل" not in case["reason"]


def test_demo_case_id_remains_compatible_with_saved_investigations():
    row = {
        "alert_type": "محاولات دخول متكررة", "source_ip": "192.0.2.1", "target": "vpn.local",
        "detection_rule": "brute_force_rate", "severity": "متوسطة", "priority_score": 1.0,
        "magnitude": 2.0,
    }
    case = make_cases(pd.DataFrame([row]), "demo", "built-in-demo-v1")[0].iloc[0]
    old_key = (row["alert_type"], row["source_ip"], row["target"], row["detection_rule"], row["severity"])
    assert case["case_id"] == "demo-" + stable_case_id(old_key)
    assert case["previous_case_id"] == "demo-" + stable_case_id(("built-in-demo-v1",) + old_key)
