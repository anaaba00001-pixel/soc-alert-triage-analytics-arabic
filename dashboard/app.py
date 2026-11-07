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


st.set_page_config(page_title="تحليل وفرز تنبيهات SOC", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    html, body, [class*="css"], .stApp { direction: rtl; text-align: right; }
    [data-testid="stSidebar"] { direction: rtl; }
    [data-testid="stDataFrame"] { direction: ltr; }
    .main .block-container { max-width: 1450px; padding-top: 1.5rem; }
    .priority-urgent { color:#ff4b4b; font-weight:800; }
    .priority-high { color:#ff9f43; font-weight:800; }
    .priority-medium { color:#feca57; font-weight:800; }
    .priority-low { color:#48dbfb; font-weight:800; }
    .hint { color:#aab2c0; font-size:.9rem; }
    div[data-testid="stMetric"] { background:#151b26; border:1px solid #293244; padding:15px; border-radius:12px; }
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


def make_cases(events: pd.DataFrame, source: str) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
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
            case_id = "demo-" + stable_case_id(tuple(key))
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
                         "sort_score": score, "source": source})
    else:
        # Exact duplicate rows are one event. Separate attempts are preserved as evidence.
        data = data.drop_duplicates(subset=ALL_COLUMNS).sort_values("alert_time")
        group_columns = ["alert_type", "source_ip", "target", "target_account", "detection_rule"]
        for key, related in data.groupby(group_columns, dropna=False, sort=False):
            related = related.sort_values("alert_time").copy()
            window = related["alert_time"].diff().gt(pd.Timedelta(minutes=5)).cumsum()
            for _, group in related.groupby(window):
                severity_value = int(group["severity"].map(SEVERITY_SCORE).max())
                count = len(group)
                burst_bonus = 2 if count >= 10 else 1 if count >= 3 else 0
                success_after = group["event_outcome"].str.lower().isin(["success", "successful", "نجاح", "ناجح"]).any()
                context_bonus = 1 if success_after and "دخول" in str(key[0]) else 0
                level = min(4, max(1, severity_value + burst_bonus + context_bonus))
                case_parts = tuple(key) + (group["alert_time"].min().floor("5min"),)
                case_id = "csv-" + stable_case_id(case_parts)
                account_text = f" إلى الحساب {key[3]}" if key[3] else ""
                reason = (
                    f"أولوية {PRIORITY_LABELS[level]} بسبب {count} حدث/أحداث من المصدر {key[1]}"
                    f" إلى {key[2]}{account_text} خلال خمس دقائق؛ الخطورة {group['severity'].iloc[0]}."
                )
                if success_after:
                    reason += " يتضمن التسلسل نتيجة ناجحة تستحق المراجعة."
                evidence[case_id] = group.copy()
                rows.append({"case_id": case_id, "first_time": group["alert_time"].min(),
                             "last_time": group["alert_time"].max(), "alert_type": key[0],
                             "source_ip": key[1], "target": key[2], "target_account": key[3],
                             "severity": group["severity"].iloc[0], "priority_level": level,
                             "priority": PRIORITY_LABELS[level], "reason": reason, "event_count": count,
                             "detection_rule": key[4] or "غير محددة", "sort_score": level * 100 + count,
                             "source": source})
    cases = pd.DataFrame(rows).sort_values(["sort_score", "last_time"], ascending=[False, False], na_position="last")
    return cases.reset_index(drop=True), evidence


def attach_investigations(cases: pd.DataFrame) -> pd.DataFrame:
    if cases.empty:
        return cases
    investigations = load_investigations()
    merged = cases.merge(investigations, on="case_id", how="left")
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
    sort_column = "sort_score" if order == "الأولوية" else "last_time"
    return result.sort_values(sort_column, ascending=False, na_position="last")


def overview(cases: pd.DataFrame, evidence: dict[str, pd.DataFrame]) -> None:
    st.subheader("نظرة عامة")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("إجمالي الحالات", f"{len(cases):,}")
    c2.metric("الحالات المفتوحة", f"{cases['status'].ne('مغلقة').sum():,}")
    c3.metric("أولوية عاجلة أو عالية", f"{cases['priority'].isin(['عاجلة', 'عالية']).sum():,}")
    c4.metric("قيد التحقيق", f"{cases['status'].eq('قيد التحقيق').sum():,}")
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
        st.markdown("#### التوزيع حسب النوع")
        st.bar_chart(cases["alert_type"].value_counts().rename("عدد الحالات"), horizontal=True)


def alerts_table(cases: pd.DataFrame) -> None:
    st.subheader("قائمة التنبيهات والحالات")
    table = cases[["last_time", "alert_type", "source_ip", "target", "severity", "priority", "status", "event_count", "case_id"]].copy()
    table.columns = ["الوقت", "نوع التنبيه", "عنوان المصدر", "الهدف", "الخطورة", "أولوية المراجعة", "حالة التحقيق", "عدد الأحداث", "معرّف الحالة"]
    st.caption(f"يعرض الجدول {len(table):,} حالة. الترتيب الافتراضي يبدأ بالأولوية الأعلى.")
    st.dataframe(table, use_container_width=True, hide_index=True)
    export = cases[["case_id", "first_time", "last_time", "alert_type", "source_ip", "target", "target_account",
                    "severity", "priority", "reason", "event_count", "detection_rule", "status", "verdict", "notes"]]
    st.download_button("⬇️ تصدير النتائج", export.to_csv(index=False).encode("utf-8-sig"),
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
    st.title("🛡️ تحليل وفرز تنبيهات مركز العمليات الأمنية")
    st.caption("من التنبيه الخام إلى حالة مرتبة، وسبب واضح، وأدلة قابلة للمراجعة، وقرار محفوظ.")

    if "data_source" not in st.session_state:
        st.session_state["data_source"] = "demo"
    action1, action2 = st.columns(2)
    if action1.button("🧪 جرّبي بيانات جاهزة", use_container_width=True,
                      type="primary" if st.session_state["data_source"] == "demo" else "secondary"):
        st.session_state["data_source"] = "demo"
        st.rerun()
    if action2.button("📤 ارفعي ملف تنبيهات", use_container_width=True):
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

    cases, evidence = make_cases(events, source)
    cases = attach_investigations(cases)
    filtered = filter_cases(cases)
    section = st.sidebar.radio("القسم", ["نظرة عامة", "قائمة التنبيهات", "تفاصيل الحالة", "أداء قواعد الكشف"])
    if section == "نظرة عامة":
        overview(filtered, evidence)
    elif section == "قائمة التنبيهات":
        alerts_table(filtered)
    elif section == "تفاصيل الحالة":
        case_details(filtered, evidence)
    else:
        rule_performance(filtered, source)


if __name__ == "__main__":
    main()
