import io

import pandas as pd

from dashboard.app import make_cases, safe_export_csv, sort_cases


def event(time, alert_type="محاولة دخول فاشلة", outcome="failure", severity="منخفضة",
          source="203.0.113.10", target="vpn.local", account="analyst"):
    return {
        "alert_time": pd.Timestamp(time, tz="Asia/Riyadh"),
        "alert_type": alert_type,
        "source_ip": source,
        "target": target,
        "target_account": account,
        "severity": severity,
        "detection_rule": "login_rule",
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
