"""Arabic SOC alert triage dashboard.

Run from the repository root with: streamlit run dashboard/app.py
"""

from __future__ import annotations

import hashlib
import io
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "dashboard" / "triage.db"
REQUIRED_COLUMNS = ["alert_time", "alert_type", "source_ip", "target"]
OPTIONAL_COLUMNS = ["target_account", "severity", "detection_rule", "event_outcome"]
ALL_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS
SEVERITY_SCORE = {"منخفضة": 1, "متوسطة": 2, "عالية": 3, "حرجة": 4}
SEVERITY_ALIASES = {
    "low": "منخفضة", "medium": "متوسطة", "high": "عالية", "critical": "حرجة",
    "منخفض": "منخفضة", "منخفضة": "منخفضة", "متوسط": "متوسطة", "متوسطة": "متوسطة",
    "عال": "عالية", "عالي": "عالية", "عالية": "عالية", "حرج": "حرجة", "حرجة": "حرجة",
}
PRIORITY_LABELS = {4: "عاجلة", 3: "عالية", 2: "متوسطة", 1: "منخفضة"}
STATUS_OPTIONS = ["جديدة", "قيد التحقيق", "مصعّدة", "مغلقة"]
VERDICT_OPTIONS = ["غير محددة", "نشاط مشبوه", "إنذار كاذب", "أدلة غير كافية"]
ARABIC_RULES = {
    "brute_force_rate": "محاولات دخول متكررة",
    "dos_flood": "حجب خدمة كثيف",
    "dos_low_and_slow": "حجب خدمة بطيء",
}


st.set_page_config(page_title="مركز مراقبة التنبيهات", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&display=swap');
    :root { --bg:#0B1020; --card:#151D33; --line:#273552; --teal:#2DD4BF; --violet:#8B5CF6; --muted:#94A3B8; }
    html, body, [class*="css"], .stApp { direction:rtl; text-align:right; font-family:'IBM Plex Sans Arabic',sans-serif; }
    .stApp { background:radial-gradient(circle at 82% 4%,rgba(139,92,246,.12),transparent 28%),var(--bg); }
    .main .block-container { max-width:1500px; padding:2rem 2.4rem 4rem; }
    [data-testid="stSidebar"] { direction:rtl; right:0; left:auto; background:linear-gradient(180deg,#10172A 0%,#0B1020 100%); border-left:1px solid var(--line); }
    [data-testid="stSidebar"] > div:first-child { padding-top:1.25rem; }
    [data-testid="stSidebar"] [role="radiogroup"] label { padding:.6rem .8rem; border-radius:10px; transition:.2s ease; }
    [data-testid="stSidebar"] [role="radiogroup"] label:hover { background:rgba(45,212,191,.08); }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#CBD5E1; }
    [data-testid="stDataFrame"] { direction:ltr; border:1px solid var(--line); border-radius:14px; overflow:hidden; }
    div[data-testid="stMetric"] { background:linear-gradient(145deg,rgba(21,29,51,.98),rgba(21,29,51,.78)); border:1px solid var(--line); padding:1rem 1.15rem; border-radius:16px; box-shadow:0 14px 35px rgba(0,0,0,.15); }
    div[data-testid="stMetric"] label { color:var(--muted); }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] { color:#F8FAFC; font-weight:700; }
    div[data-testid="stVerticalBlockBorderWrapper"] { background:rgba(21,29,51,.72); border-color:var(--line)!important; border-radius:16px; }
    .stButton button, .stDownloadButton button, [data-testid="stFormSubmitButton"] button { border-radius:10px; border-color:rgba(45,212,191,.48); transition:transform .18s ease,box-shadow .18s ease; }
    .stButton button:hover, .stDownloadButton button:hover, [data-testid="stFormSubmitButton"] button:hover { transform:translateY(-1px); box-shadow:0 0 22px rgba(45,212,191,.22); border-color:var(--teal); }
    .hero { display:flex; align-items:center; justify-content:space-between; gap:1rem; margin-bottom:1.25rem; }
    .hero h1 { margin:0; font-size:2rem; letter-spacing:-.02em; }
    .hero p { margin:.35rem 0 0; color:var(--muted); }
    .eyebrow { color:var(--teal); font-size:.78rem; font-weight:700; letter-spacing:.08em; }
    .side-brand { display:flex; gap:.75rem; align-items:center; padding:.8rem .55rem 1.25rem; border-bottom:1px solid var(--line); margin-bottom:1rem; }
    .shield { width:42px; height:42px; display:grid; place-items:center; border-radius:13px; color:#07111D; background:linear-gradient(135deg,var(--teal),var(--violet)); box-shadow:0 0 24px rgba(45,212,191,.2); font-size:1.3rem; }
    .side-brand strong { display:block; color:#F8FAFC; } .side-brand small { color:var(--muted); }
    .section-title { margin-top:.35rem; color:#F8FAFC; font-size:1.15rem; font-weight:700; }
    code, .ltr { direction:ltr; unicode-bidi:embed; display:inline-block; }
    h1,h2,h3,h4 { color:#F8FAFC; }
    [data-testid="stAlert"] { border-radius:12px; border-color:var(--line); }
    @media(max-width:900px){ .main .block-container{padding:1.2rem}.hero{align-items:flex-start}.hero h1{font-size:1.55rem} }
    </style>
    """,
    unsafe_allow_html=True,
)


def db_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS investigations (
            case_id TEXT PRIMARY KEY, status TEXT NOT NULL, verdict TEXT NOT NULL,
            notes TEXT NOT NULL, updated_at TEXT NOT NULL
        )"""
    )
    connection.commit()
    return connection


def load_investigations() -> pd.DataFrame:
    with db_connection() as connection:
        return pd.read_sql_query("SELECT * FROM investigations", connection)


def save_investigation(case_id: str, status: str, verdict: str, notes: str) -> None:
    now = pd.Timestamp.now(tz="Asia/Riyadh").isoformat()
    with db_connection() as connection:
        connection.execute(
            """INSERT INTO investigations(case_id, status, verdict, notes, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(case_id) DO UPDATE SET status=excluded.status,
               verdict=excluded.verdict, notes=excluded.notes, updated_at=excluded.updated_at""",
            (case_id, status, verdict, notes, now),
        )
        connection.commit()


@st.cache_data(show_spinner="جارٍ تحميل البيانات التجريبية…")
def load_demo_queue() -> pd.DataFrame:
    queue = pd.read_csv(ROOT / "priority_queue.csv")
    queue = queue.drop(columns=[c for c in queue.columns if c.startswith("Unnamed")], errors="ignore")
    queue["is_fp"] = queue["is_fp"].astype(str).str.lower().eq("true")
    queue["alert_time"] = pd.NaT
    queue["alert_type"] = queue["rule"].map(ARABIC_RULES).fillna(queue["rule"])
    queue["source_ip"] = queue["Source IP"].astype(str)
    queue["target"] = queue["Destination IP"].astype(str)
    queue["target_account"] = ""
    queue["detection_rule"] = queue["rule"]
    queue["severity"] = queue["rule"].map(
        {"brute_force_rate": "متوسطة", "dos_flood": "عالية", "dos_low_and_slow": "عالية"}
    ).fillna("متوسطة")
    queue["event_outcome"] = ""
    queue["original_order"] = range(len(queue))
    return queue


@st.cache_data
def load_scorecard() -> pd.DataFrame:
    return pd.read_csv(ROOT / "results.csv")


def template_csv() -> bytes:
    sample = pd.DataFrame([
        {
            "alert_time": "2026-11-07 09:00:00+03:00", "alert_type": "محاولة دخول فاشلة",
            "source_ip": "203.0.113.10", "target": "vpn.example.local", "target_account": "analyst",
            "severity": "high", "detection_rule": "repeated_login", "event_outcome": "failure",
        }
    ])
    return sample.to_csv(index=False).encode("utf-8-sig")


def validate_upload(raw: bytes) -> tuple[pd.DataFrame | None, pd.DataFrame]:
    try:
        frame = pd.read_csv(io.BytesIO(raw))
    except Exception as exc:
        return None, pd.DataFrame({"الصف": ["الملف"], "سبب المشكلة": [f"تعذرت قراءة CSV: {exc}"]})

    frame.columns = frame.columns.str.strip().str.lower()
    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        return None, pd.DataFrame({
            "الصف": ["الأعمدة"],
            "سبب المشكلة": ["أعمدة مطلوبة مفقودة: " + ", ".join(missing)],
        })
    for column in OPTIONAL_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    frame = frame[ALL_COLUMNS].copy()
    frame["_row"] = frame.index + 2
    parsed_time = pd.to_datetime(frame["alert_time"], errors="coerce", utc=True)
    problems: list[dict] = []
    for index, row in frame.iterrows():
        reasons = []
        if pd.isna(parsed_time.loc[index]):
            reasons.append("وقت غير صالح")
        for column, label in [("alert_type", "نوع التنبيه"), ("source_ip", "عنوان المصدر"), ("target", "الهدف")]:
            if pd.isna(row[column]) or not str(row[column]).strip():
                reasons.append(f"{label} مفقود")
        if reasons:
            problems.append({"الصف": int(row["_row"]), "سبب المشكلة": "، ".join(reasons)})
    valid = frame.loc[~frame["_row"].isin([p["الصف"] for p in problems])].copy()
    valid["alert_time"] = parsed_time.loc[valid.index].dt.tz_convert("Asia/Riyadh")
    valid["severity"] = valid["severity"].fillna("متوسطة").astype(str).str.strip().str.lower().map(SEVERITY_ALIASES).fillna("متوسطة")
    for column in ["alert_type", "source_ip", "target", "target_account", "detection_rule", "event_outcome"]:
        valid[column] = valid[column].fillna("").astype(str).str.strip()
    valid = valid.drop(columns="_row")
    return valid, pd.DataFrame(problems, columns=["الصف", "سبب المشكلة"])


def stable_case_id(parts: tuple) -> str:
    value = "|".join(str(part) for part in parts)
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def fixed_five_minute_windows(times: pd.Series) -> pd.Series:
    """Assign windows whose duration is measured from the first event."""
    window_ids: list[int] = []
    window_id = 0
    window_start = None
    for event_time in times:
        if window_start is None or event_time - window_start > pd.Timedelta(minutes=5):
            window_id += 1
            window_start = event_time
        window_ids.append(window_id)
    return pd.Series(window_ids, index=times.index)


LOGIN_WORDS = ("login", "logon", "sign-in", "sign in", "تسجيل دخول", "محاولة دخول")
FAILURE_OUTCOMES = {"failure", "failed", "fail", "فشل", "فاشل"}
SUCCESS_OUTCOMES = {"success", "successful", "succeeded", "نجاح", "ناجح"}


def is_login_event(row: pd.Series) -> bool:
    text = f"{row.get('alert_type', '')} {row.get('detection_rule', '')}".lower()
    return any(word in text for word in LOGIN_WORDS)


def classify_outcome(row: pd.Series) -> str:
    """Prefer the explicit outcome; infer from the alert type only when it is blank."""
    explicit = str(row.get("event_outcome", "") or "").strip().lower()
    if explicit:
        if explicit in FAILURE_OUTCOMES:
            return "failure"
        if explicit in SUCCESS_OUTCOMES:
            return "success"
        return "other"

    description = str(row.get("alert_type", "") or "").strip().lower()
    # Failure must be checked first because "unsuccessful" contains "successful".
    if any(word in description for word in ("unsuccessful", "failed", "failure", "فاشل", "فشل")):
        return "failure"
    if any(word in description for word in ("successful", "succeeded", "success", "ناجح", "نجاح")):
        return "success"
    return "other"


def has_failure_then_success(group: pd.DataFrame) -> bool:
    if not str(group["target_account"].iloc[0]).strip() or not group.apply(is_login_event, axis=1).all():
        return False
    outcomes = group.apply(classify_outcome, axis=1)
    failures = outcomes.eq("failure")
    successes = outcomes.eq("success")
    if not failures.any() or not successes.any():
        return False
    return group.loc[successes, "alert_time"].max() > group.loc[failures, "alert_time"].min()


def highest_severity(group: pd.DataFrame) -> tuple[str, int]:
    scores = group["severity"].map(SEVERITY_SCORE).fillna(SEVERITY_SCORE["متوسطة"])
    score = int(scores.max())
    label = next(label for label, value in SEVERITY_SCORE.items() if value == score)
    return label, score


def sort_cases(cases: pd.DataFrame) -> pd.DataFrame:
    return cases.sort_values(
        ["priority_level", "event_count", "last_time"],
        ascending=[False, False, False],
        na_position="last",
    )


def make_cases(events: pd.DataFrame, source: str, dataset_id: str = "demo") -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    if events.empty:
        return pd.DataFrame(), {}
    data = events.copy()
    evidence: dict[str, pd.DataFrame] = {}
    rows: list[dict] = []

    if source == "demo":
        # The original queue remains ordered by its stored rule-confidence and threshold magnitude.
        group_columns = ["alert_type", "source_ip", "target", "detection_rule", "severity"]
        for key, group in data.groupby(group_columns, dropna=False, sort=False):
            first = group.iloc[0]
            score = float(group["priority_score"].max())
            level = 4 if score >= 2.5 else 3 if score >= 2 else 2 if score >= 1 else 1
            # Preserve the identifier used before upload isolation so existing
            # SQLite investigations for the built-in demo become visible again.
            case_id = "demo-" + stable_case_id(tuple(key))
            previous_case_id = "demo-" + stable_case_id((dataset_id,) + tuple(key))
            reason = (
                f"{PRIORITY_LABELS[level]} وفق ترتيب المشروع الأصلي: وزن القاعدة × دقتها = {score:.3f}، "
                f"وأعلى مقدار تجاوز للعتبة {group['magnitude'].max():.2f}."
            )
            event_count = len(group)
            first_time = pd.NaT
            last_time = pd.NaT
            evidence[case_id] = group.head(500).copy()
            rows.append({"case_id": case_id, "first_time": first_time, "last_time": last_time,
                         "alert_type": first["alert_type"], "source_ip": first["source_ip"],
                         "target": first["target"], "target_account": "", "severity": first["severity"],
                         "priority_level": level, "priority": PRIORITY_LABELS[level], "reason": reason,
                         "event_count": event_count, "detection_rule": first["detection_rule"],
                         "previous_case_id": previous_case_id, "source": source})
    else:
        # Exact duplicate rows are one event. Separate attempts are preserved as evidence.
        data = data.drop_duplicates(subset=ALL_COLUMNS).sort_values("alert_time")
        # Login variants share a family. Other alert types remain separate even if
        # source, target and account happen to match.
        data["_event_family"] = data.apply(
            lambda row: "__login__" if is_login_event(row)
            else f"{row['alert_type']}|{row['detection_rule']}",
            axis=1,
        )
        group_columns = ["source_ip", "target", "target_account", "_event_family"]
        for key, related in data.groupby(group_columns, dropna=False, sort=False):
            related = related.sort_values("alert_time").copy()
            window = fixed_five_minute_windows(related["alert_time"])
            for _, group in related.groupby(window):
                severity_label, severity_value = highest_severity(group)
                count = len(group)
                burst_bonus = 2 if count >= 10 else 1 if count >= 3 else 0
                success_after_failure = has_failure_then_success(group)
                context_bonus = 1 if success_after_failure else 0
                level = min(4, max(1, severity_value + burst_bonus + context_bonus))
                identity_key = tuple(key[:3])
                case_parts = (dataset_id,) + identity_key + (group["alert_time"].min().isoformat(),)
                if key[3] != "__login__":
                    case_parts += (key[3],)
                case_id = "csv-" + stable_case_id(case_parts)
                account_text = f" إلى الحساب {key[2]}" if key[2] else ""
                alert_types = " / ".join(dict.fromkeys(group["alert_type"].astype(str)))
                detection_rules = " / ".join(filter(None, dict.fromkeys(group["detection_rule"].astype(str)))) or "غير محددة"
                duration = group["alert_time"].max() - group["alert_time"].min()
                duration_minutes = duration.total_seconds() / 60
                reason = (
                    f"أولوية {PRIORITY_LABELS[level]} بسبب {count} حدث/أحداث من المصدر {key[0]}"
                    f" إلى {key[1]}{account_text} خلال {duration_minutes:.1f} دقيقة؛ الخطورة الأعلى {severity_label}."
                )
                if success_after_failure:
                    reason += " رُصد نجاح دخول بعد فشل للمصدر والهدف والحساب أنفسهم."
                evidence[case_id] = group.drop(columns="_event_family").copy()
                rows.append({"case_id": case_id, "first_time": group["alert_time"].min(),
                             "last_time": group["alert_time"].max(), "alert_type": alert_types,
                             "source_ip": key[0], "target": key[1], "target_account": key[2],
                             "severity": severity_label, "priority_level": level,
                             "priority": PRIORITY_LABELS[level], "reason": reason, "event_count": count,
                             "detection_rule": detection_rules,
                             "previous_case_id": "", "source": source})
    cases = sort_cases(pd.DataFrame(rows))
    return cases.reset_index(drop=True), evidence


def attach_investigations(cases: pd.DataFrame) -> pd.DataFrame:
    if cases.empty:
        return cases
    investigations = load_investigations().set_index("case_id")
    merged = cases.copy()
    investigation_columns = ["status", "verdict", "notes", "updated_at"]
    for column in investigation_columns:
        merged[column] = merged["case_id"].map(investigations[column])
        if "previous_case_id" in merged:
            fallback = merged["previous_case_id"].map(investigations[column])
            merged[column] = merged[column].fillna(fallback)
    merged["status"] = merged["status"].fillna("جديدة")
    merged["verdict"] = merged["verdict"].fillna("غير محددة")
    merged["notes"] = merged["notes"].fillna("")
    merged["updated_at"] = merged["updated_at"].fillna("")
    return merged


def show_upload() -> tuple[pd.DataFrame | None, str]:
    st.subheader("رفع ملف تنبيهات CSV")
    st.caption("هذه النسخة تستقبل تنبيهات جاهزة؛ استيراد سجلات الشبكة الخام وتشغيل قواعد الكشف عليها إضافة لاحقة.")
    st.download_button("⬇️ تحميل قالب CSV", template_csv(), "alert_template.csv", "text/csv")
    uploaded = st.file_uploader("ارفعي ملف تنبيهات", type=["csv"], label_visibility="collapsed")
    if not uploaded:
        return None, "demo"
    fingerprint = hashlib.sha1(uploaded.getvalue()).hexdigest()[:12]
    valid, problems = validate_upload(uploaded.getvalue())
    if valid is None:
        st.error("تعذر قبول الملف.")
        st.dataframe(problems, use_container_width=True, hide_index=True)
        return None, "demo"
    col1, col2, col3 = st.columns(3)
    col1.metric("إجمالي الصفوف", len(valid) + len(problems))
    col2.metric("صفوف مقبولة", len(valid))
    col3.metric("تحتاج تصحيحًا", len(problems))
    st.markdown("#### معاينة الصفوف المقبولة")
    st.dataframe(valid.head(20), use_container_width=True, hide_index=True)
    if not problems.empty:
        with st.expander("الصفوف التي تحتاج تصحيحًا", expanded=True):
            st.dataframe(problems, use_container_width=True, hide_index=True)
    if valid.empty:
        st.warning("لا توجد صفوف صالحة للتحليل.")
        return None, "demo"
    if st.button("تحليل الصفوف المقبولة", type="primary", use_container_width=True):
        with st.spinner("جارٍ التحقق من الحقول وتجميع التنبيهات وحساب الأولوية…"):
            st.session_state["uploaded_events"] = valid
            st.session_state["upload_id"] = fingerprint
            st.session_state["data_source"] = "upload"
        st.rerun()
    return None, "demo"


def filter_cases(cases: pd.DataFrame) -> pd.DataFrame:
    st.sidebar.header("البحث والتصفية")
    search = st.sidebar.text_input("IP أو الحساب أو الهدف")
    types = sorted(cases["alert_type"].dropna().unique())
    chosen_types = st.sidebar.multiselect("نوع التنبيه", types, default=types)
    priorities = [p for p in ["عاجلة", "عالية", "متوسطة", "منخفضة"] if p in set(cases["priority"])]
    chosen_priorities = st.sidebar.multiselect("الأولوية", priorities, default=priorities)
    chosen_status = st.sidebar.multiselect("حالة التحقيق", STATUS_OPTIONS, default=STATUS_OPTIONS)
    result = cases[
        cases["alert_type"].isin(chosen_types)
        & cases["priority"].isin(chosen_priorities)
        & cases["status"].isin(chosen_status)
    ]
    if search:
        mask = pd.Series(False, index=result.index)
        for column in ["source_ip", "target", "target_account"]:
            mask |= result[column].astype(str).str.contains(search, case=False, na=False, regex=False)
        result = result[mask]
    if result["last_time"].notna().any():
        min_date = result["last_time"].min().date()
        max_date = result["last_time"].max().date()
        date_range = st.sidebar.date_input("الفترة", value=(min_date, max_date), min_value=min_date, max_value=max_date)
        if isinstance(date_range, tuple) and len(date_range) == 2:
            dates = result["last_time"].dt.date
            result = result[(dates >= date_range[0]) & (dates <= date_range[1])]
    order = st.sidebar.radio("الترتيب", ["الأولوية", "الأحدث"])
    if order == "الأولوية":
        return sort_cases(result)
    return result.sort_values("last_time", ascending=False, na_position="last")


def overview(cases: pd.DataFrame, evidence: dict[str, pd.DataFrame]) -> None:
    st.markdown('<div class="section-title">نظرة عامة على الحالات</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("◉ إجمالي الحالات", f"{len(cases):,}")
    c2.metric("⚠ العاجلة", f"{cases['priority'].eq('عاجلة').sum():,}")
    c3.metric("⌕ قيد التحقيق", f"{cases['status'].eq('قيد التحقيق').sum():,}")
    c4.metric("✓ المغلقة", f"{cases['status'].eq('مغلقة').sum():,}")
    left, right = st.columns(2)
    timed = cases.dropna(subset=["last_time"])
    with left:
        st.markdown("#### زيادة التنبيهات عبر الوقت")
        if timed.empty:
            st.info("البيانات التجريبية المرتبة لا تحتوي وقت التنبيه. ارفعي CSV لعرض المنحنى الزمني.")
        else:
            events = pd.concat([frame for cid, frame in evidence.items() if cid in set(cases["case_id"])], ignore_index=True)
            series = events.set_index("alert_time").resample("h").size().rename("عدد التنبيهات")
            st.line_chart(series)
    with right:
        st.markdown("#### توزيع الأولويات")
        priority_order = ["عاجلة", "عالية", "متوسطة", "منخفضة"]
        distribution = cases["priority"].value_counts().reindex(priority_order, fill_value=0).rename("عدد الحالات")
        st.bar_chart(distribution, horizontal=True, color="#8B5CF6")


def sanitize_spreadsheet_value(value):
    """Prevent untrusted CSV text from being interpreted as a spreadsheet formula."""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def safe_export_csv(cases: pd.DataFrame) -> bytes:
    export_columns = ["case_id", "first_time", "last_time", "alert_type", "source_ip", "target",
                      "target_account", "severity", "priority", "reason", "event_count",
                      "detection_rule", "status", "verdict", "notes"]
    export = cases[export_columns].copy()
    for column in export.select_dtypes(include=["object", "string"]).columns:
        export[column] = export[column].map(sanitize_spreadsheet_value)
    return export.to_csv(index=False).encode("utf-8-sig")


def alerts_table(cases: pd.DataFrame) -> None:
    st.subheader("قائمة التنبيهات والحالات")
    table = cases[["last_time", "alert_type", "source_ip", "target", "severity", "priority", "status", "event_count", "case_id"]].copy()
    table.columns = ["الوقت", "نوع التنبيه", "عنوان المصدر", "الهدف", "الخطورة", "أولوية المراجعة", "حالة التحقيق", "عدد الأحداث", "معرّف الحالة"]
    st.caption(f"يعرض الجدول {len(table):,} حالة. الترتيب الافتراضي يبدأ بالأولوية الأعلى.")
    priority_colors = {"عاجلة": "#FB7185", "عالية": "#FB923C", "متوسطة": "#FACC15", "منخفضة": "#2DD4BF"}
    status_colors = {"جديدة": "#8B5CF6", "قيد التحقيق": "#2DD4BF", "مصعّدة": "#FB923C", "مغلقة": "#64748B"}
    def color_badges(value):
        color = priority_colors.get(str(value), status_colors.get(str(value)))
        return f"color:{color};font-weight:700" if color else ""
    styled = table.style.applymap(color_badges, subset=["أولوية المراجعة", "حالة التحقيق"])
    st.dataframe(styled, use_container_width=True, hide_index=True, height=520)
    st.download_button("⬇️ تصدير النتائج", safe_export_csv(cases),
                       "triage_cases.csv", "text/csv", use_container_width=True)


def case_details(cases: pd.DataFrame, evidence: dict[str, pd.DataFrame]) -> None:
    st.subheader("تفاصيل الحالة والتحقيق")
    if cases.empty:
        st.info("لا توجد حالة تطابق الفلاتر.")
        return
    labels = {
        row.case_id: f"{row.priority} — {row.alert_type} — {row.source_ip} ← {row.target} ({row.case_id})"
        for row in cases.itertuples()
    }
    selected_id = st.selectbox("اختاري حالة", cases["case_id"].tolist(), format_func=lambda value: labels[value])
    case = cases.loc[cases["case_id"] == selected_id].iloc[0]
    st.markdown(f"### {case['priority']} · {case['alert_type']}")
    st.info(case["reason"])
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("أول رصد", str(case["first_time"]) if pd.notna(case["first_time"]) else "غير متاح")
    c2.metric("آخر رصد", str(case["last_time"]) if pd.notna(case["last_time"]) else "غير متاح")
    c3.metric("عدد الأحداث", int(case["event_count"]))
    c4.metric("قاعدة الكشف", case["detection_rule"])
    st.markdown(f"**المصدر:** `{case['source_ip']}` &nbsp;&nbsp; **الهدف:** `{case['target']}`"
                + (f" &nbsp;&nbsp; **الحساب:** `{case['target_account']}`" if case["target_account"] else ""),
                unsafe_allow_html=True)
    with st.expander("الخط الزمني والسجلات التي بُنيت عليها الحالة", expanded=True):
        raw = evidence.get(selected_id, pd.DataFrame()).copy()
        shown_count = len(raw)
        total_count = int(case["event_count"])
        if shown_count < total_count:
            st.warning(f"تعرض التفاصيل أول {shown_count:,} سجلًا من أصل {total_count:,} سجلًا في هذه الحالة.")
        else:
            st.caption(f"تعرض التفاصيل جميع السجلات وعددها {shown_count:,}.")
        if "alert_time" in raw and raw["alert_time"].notna().any():
            timeline = raw[["alert_time", "alert_type", "source_ip", "target", "target_account", "event_outcome", "severity"]]
            st.dataframe(timeline.sort_values("alert_time"), use_container_width=True, hide_index=True)
        else:
            st.caption("البيانات الأصلية لا توفر طابعًا زمنيًا في قائمة الأولوية المحفوظة.")
            st.dataframe(raw, use_container_width=True, hide_index=True)
    with st.form(f"investigation-{selected_id}"):
        status_index = STATUS_OPTIONS.index(case["status"]) if case["status"] in STATUS_OPTIONS else 0
        verdict_index = VERDICT_OPTIONS.index(case["verdict"]) if case["verdict"] in VERDICT_OPTIONS else 0
        status = st.selectbox("حالة العمل", STATUS_OPTIONS, index=status_index)
        verdict = st.selectbox("نتيجة المراجعة", VERDICT_OPTIONS, index=verdict_index)
        notes = st.text_area("ملاحظات المحللة", value=case["notes"], height=120)
        if st.form_submit_button("حفظ التحقيق", type="primary", use_container_width=True):
            save_investigation(selected_id, status, verdict, notes)
            st.success("حُفظ القرار والملاحظات محليًا.")
            st.rerun()


def rule_performance(cases: pd.DataFrame, source: str) -> None:
    st.subheader("أداء قواعد الكشف")
    if source == "demo":
        scorecard = load_scorecard().copy()
        scorecard["القاعدة"] = scorecard["rule"].map(ARABIC_RULES).fillna(scorecard["rule"])
        scorecard["عدد التنبيهات"] = scorecard["alerts"]
        scorecard["الدقة"] = scorecard["precision"].map(lambda x: f"{x:.1%}")
        scorecard["نسبة الهجمات المكتشفة"] = scorecard["recall"].map(lambda x: f"{x:.1%}")
        st.dataframe(scorecard[["القاعدة", "عدد التنبيهات", "الدقة", "نسبة الهجمات المكتشفة"]],
                     use_container_width=True, hide_index=True)
        st.caption("الدقة والاستدعاء محسوبان من بيانات الاختبار المصنّفة المرفقة بالمشروع.")
        st.image(str(ROOT / "figures" / "coverage_curve.png"), caption="تغطية الترتيب الأصلي مقابل الضوضاء المتجاوزة")
    else:
        grouped = cases.groupby("detection_rule", dropna=False).agg(
            **{"عدد التنبيهات": ("event_count", "sum"), "عدد الحالات": ("case_id", "count"),
               "نشاط مشبوه": ("verdict", lambda values: (values == "نشاط مشبوه").sum()),
               "إنذارات كاذبة": ("verdict", lambda values: (values == "إنذار كاذب").sum())}
        ).reset_index().rename(columns={"detection_rule": "القاعدة"})
        grouped["الدقة"] = "بيانات التقييم غير متاحة"
        grouped["نسبة الهجمات المكتشفة"] = "بيانات التقييم غير متاحة"
        st.dataframe(grouped, use_container_width=True, hide_index=True)
        st.caption("لا يحتوي الملف المرفوع تصنيفًا مرجعيًا؛ لذلك تعرض الصفحة الحجم ونتائج المراجعة المسجّلة فقط.")


def main() -> None:
    if "data_source" not in st.session_state:
        st.session_state["data_source"] = "demo"

    st.sidebar.markdown(
        '<div class="side-brand"><div class="shield">🛡</div><div><strong>مرصد SOC</strong><small>تحليل وفرز التنبيهات</small></div></div>',
        unsafe_allow_html=True,
    )
    section = st.sidebar.radio("التنقل", ["نظرة عامة", "التنبيهات", "التحقيقات", "أداء الكشف"], label_visibility="collapsed")

    source_name = "priority_queue.csv" if st.session_state["data_source"] == "demo" else "الملف المرفوع"
    last_analysis = pd.Timestamp.now(tz="Asia/Riyadh").strftime("%H:%M، %d/%m/%Y")
    st.markdown(
        f'<div class="hero"><div><div class="eyebrow">مركز العمليات الأمنية</div><h1>مركز مراقبة التنبيهات</h1>'
        f'<p>الملف الجاري تحليله: <span class="ltr">{source_name}</span> · آخر تحليل: {last_analysis}</p></div></div>',
        unsafe_allow_html=True,
    )
    header_space, upload_action = st.columns([5, 1])
    with header_space:
        st.caption("راقب الأولويات، راجع الأدلة، واحفظ قرارات التحقيق من مكان واحد.")
    if upload_action.button("＋ رفع ملف", type="primary", use_container_width=True):
        st.session_state["show_upload"] = True

    if st.session_state.get("show_upload"):
        with st.container(border=True):
            show_upload()

    source = st.session_state["data_source"]
    if source == "upload" and "uploaded_events" in st.session_state:
        events = st.session_state["uploaded_events"]
        st.success(f"يتم تحليل الملف المرفوع: {len(events):,} صف مقبول.")
    else:
        source = "demo"
        events = load_demo_queue()
        st.caption("مصدر البيانات الحالي: بيانات المشروع الأصلية المرتبة.")

    dataset_id = "built-in-demo-v1" if source == "demo" else st.session_state.get("upload_id", "unknown-upload")
    cases, evidence = make_cases(events, source, dataset_id)
    cases = attach_investigations(cases)
    filtered = filter_cases(cases)
    if section == "نظرة عامة":
        overview(filtered, evidence)
    elif section == "التنبيهات":
        alerts_table(filtered)
    elif section == "التحقيقات":
        case_details(filtered, evidence)
    else:
        rule_performance(filtered, source)


if __name__ == "__main__":
    main()
