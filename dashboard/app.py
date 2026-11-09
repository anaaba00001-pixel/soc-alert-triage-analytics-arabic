"""Arabic SOC alert triage dashboard.

Run from the repository root with: streamlit run dashboard/app.py
"""

from __future__ import annotations

import hashlib
import html
import io
import json
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
PALETTES = {
    False: {
        "page": "#F4F6F4", "panel": "#FFFFFF", "soft": "#F8FAF8", "text": "#1D3026",
        "muted": "#708078", "line": "#E5EBE6", "accent": "#157347", "tint": "#E6F3EB",
        "shadow": "0 5px 24px rgba(25,60,40,.035)", "color-scheme": "light",
    },
    True: {
        "page": "#101B16", "panel": "#19271F", "soft": "#213228", "text": "#EAF3ED",
        "muted": "#A7BAAC", "line": "#304337", "accent": "#83D9AB", "tint": "#284735",
        "shadow": "0 5px 24px rgba(0,0,0,.12)", "color-scheme": "dark",
    },
}


DASHBOARD_STYLES = r"""
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&display=swap');
html, body, .stApp { direction:rtl; font-family:'IBM Plex Sans Arabic',sans-serif; }
.stApp { background:var(--page); color:var(--text); color-scheme:var(--color-scheme); }
[data-testid="stAppViewContainer"] { background:var(--page); }
[data-testid="stHeader"] { background:var(--page); color:var(--text); }
[data-testid="stMainBlockContainer"] { max-width:1450px; padding:2.2rem 2.2rem 3rem; }
[data-testid="stSidebar"] { right:0; left:auto; background:var(--panel); border-left:1px solid var(--line); color:var(--text); }
[data-testid="stSidebarContent"] { padding-top:1rem; }
h1,h2,h3,h4,h5,h6,p,label, [data-testid="stWidgetLabel"] { color:var(--text); font-family:'IBM Plex Sans Arabic',sans-serif; }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p { color:var(--muted); font-size:.8rem; }
[data-testid="stSidebar"] [role="radiogroup"] label { padding:.65rem .8rem; border-radius:10px; transition:background .18s ease; }
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) { background:var(--tint); color:var(--accent); box-shadow:inset -3px 0 var(--accent); font-weight:600; }
[data-testid="stSidebar"] [role="radiogroup"] label:hover { background:var(--soft); }
.side-brand { display:flex; gap:.8rem; align-items:center; padding:1rem 0 1.75rem; }
.brand-symbol { width:38px;height:38px;border:2px solid var(--accent);color:var(--accent);border-radius:50%;display:grid;place-items:center;font-size:30px;line-height:1; }
.side-brand strong { display:block; font-size:1.35rem; letter-spacing:-.5px; color:var(--text); }
.side-brand small { display:block; color:var(--muted); font-size:.68rem; }
.nav-label { color:var(--muted); font-size:.68rem; margin-bottom:.6rem; }
.hero { margin:.4rem 0 .3rem; }
.hero h1 { margin:0; padding:.2rem 0; font-size:2rem; font-weight:600; letter-spacing:-.7px; }
.hero p { margin:.35rem 0 0; color:var(--muted); font-size:.78rem; }
.eyebrow { color:var(--accent); font-size:.73rem; font-weight:500; }
.stButton button,.stDownloadButton button,[data-testid="stFormSubmitButton"] button { min-height:2.5rem; border-radius:25px; border:1px solid var(--line); background:var(--panel); color:var(--text); font-family:inherit; font-size:.85rem; transition:transform .15s ease; }
.stButton button:hover,.stDownloadButton button:hover { border-color:var(--accent); color:var(--accent); transform:translateY(-1px); }
.stButton button[kind="primary"], [data-testid="stBaseButton-primary"], [data-testid="stFormSubmitButton"] button { background:#176B45; color:#FFF; border-color:#176B45; }
.stButton button[kind="primary"] p, [data-testid="stBaseButton-primary"] p, [data-testid="stFormSubmitButton"] button p { color:#FFF; }
[data-testid="stMetric"] { background:var(--panel); border:1px solid var(--line); border-radius:18px; padding:1.15rem 1.2rem .9rem; box-shadow:var(--shadow); }
[data-testid="stMetricLabel"] p { color:var(--text); font-size:.83rem; }
[data-testid="stMetricValue"] { color:var(--text); font-weight:500; font-size:2.6rem; }
[data-testid="stMetricDelta"] { color:var(--muted); font-size:.67rem; }
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-child [data-testid="stMetric"] { background:linear-gradient(140deg,#135C3A,#228455); border-color:#228455; }
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-child [data-testid="stMetric"] p, [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-child [data-testid="stMetricValue"] { color:#FFF; }
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-child [data-testid="stMetricDelta"] { color:#BFE3CB; }
[data-testid="stVerticalBlockBorderWrapper"], [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"] > [data-testid="stVerticalBlockBorderWrapper"] { background:var(--panel); border-color:var(--line)!important; border-radius:18px; box-shadow:var(--shadow); }
[data-testid="stVerticalBlockBorderWrapper"] h4 { margin:0; padding:0 0 .2rem; font-size:1rem; font-weight:600; }
[data-testid="stTextInput"] input,[data-testid="stTextArea"] textarea,[role="combobox"] { background:var(--soft)!important; color:var(--text)!important; border-radius:10px; }
[data-testid="stTextInput"] > div,[data-testid="stTextArea"] > div { background:var(--soft); border-color:var(--line); }
[data-testid="stSidebar"] [data-testid="stMultiSelect"] { font-size:.8rem; }
[data-testid="stFileUploaderDropzone"] { background:var(--soft); color:var(--text); border:1px dashed var(--accent); border-radius:16px; }
[data-testid="stAlert"] { background:var(--tint); color:var(--text); border:1px solid var(--line); border-radius:12px; }
[data-testid="stDataFrame"] { direction:ltr; border:1px solid var(--line); border-radius:14px; overflow:hidden; }
[data-testid="stExpander"] { background:var(--panel); color:var(--text); border-color:var(--line); border-radius:14px; }
[data-testid="stForm"] { background:var(--panel); border-color:var(--line); border-radius:14px; }
.empty-chart { height:195px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center; }
.empty-chart>span { width:44px;height:44px;display:grid;place-items:center;background:var(--tint);border-radius:50%;color:var(--accent);font-size:1.7rem;margin-bottom:.8rem; }
.empty-chart strong { font-weight:500; color:var(--text); font-size:.9rem; }
.empty-chart p { max-width:280px;color:var(--muted);font-size:.75rem;margin-top:.5rem; }
.activity-row { display:flex;align-items:center;gap:.65rem;padding:.7rem 0;border-bottom:1px solid var(--line); }
.activity-row:last-child { border-bottom:0; }
.activity-icon { width:34px;height:34px;flex-shrink:0;display:grid;place-items:center;border-radius:50%;background:var(--tint);color:var(--accent);font-size:1.2rem; }
.activity-info { flex:1;min-width:0; }
.activity-info strong { display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.8rem;font-weight:500;color:var(--text); }
.activity-info span { color:var(--muted);font-size:.69rem; }
.badge { padding:.2rem .55rem;border-radius:6px;font-size:.66rem; }
.badge.urgent { background:#F8E4DF;color:#8E3B31; }.badge.high { background:#F9EED7;color:#855D19; }.badge.medium { background:#E5F2E8;color:#27623D; }.badge.low { background:#EEF3EF;color:#446F54; }
.progress-ring { width:184px;height:184px;border-radius:50%;margin:.8rem auto;background:conic-gradient(#238354 var(--progress),var(--tint) 0);display:grid;place-items:center; }
.progress-ring>div { width:148px;height:148px;border-radius:50%;background:var(--panel);display:flex;align-items:center;justify-content:center;flex-direction:column; }
.progress-ring strong { font-size:2.6rem;font-weight:500;color:var(--text);direction:ltr; }.progress-ring span { color:var(--muted);font-size:.7rem; }
.ring-legend { display:flex;justify-content:center;gap:1.2rem;font-size:.72rem;color:var(--muted);padding-bottom:.3rem; }
.ring-legend i { display:inline-block;width:7px;height:7px;background:#238354;border-radius:50%;margin-left:.4rem; }
.case-panel { border:1px solid var(--line);border-radius:16px;background:var(--panel);padding:1rem; }.case-panel h3{font-size:1.15rem;}.case-panel p{color:var(--text);font-size:.85rem;line-height:1.8}.priority{font-size:.78rem;font-weight:600}
code,.ltr { direction:ltr;unicode-bidi:embed;display:inline-block; }
@media(max-width:900px){ [data-testid="stMainBlockContainer"]{padding:1rem}.hero h1{font-size:1.5rem}[data-testid="stMetric"]{padding:.7rem}.progress-ring{width:154px;height:154px}.progress-ring>div{width:124px;height:124px} }
@media(prefers-reduced-motion:reduce){ *{transition:none!important} }

.hero { text-align:right; }
.st-key-trend-panel,.st-key-priority-panel,.st-key-activity-panel,.st-key-completion-panel { background:var(--panel); border-color:var(--line)!important; border-radius:18px; box-shadow:var(--shadow); }
.st-key-trend-panel h4,.st-key-priority-panel h4,.st-key-activity-panel h4,.st-key-completion-panel h4 { font-size:1rem; font-weight:600; padding-top:.2rem; padding-bottom:0; }
[data-testid="stMultiSelect"] .react-aria-ComboBox,[data-testid="stMultiSelect"] [data-rac][role="group"],[data-testid="stSelectbox"] [role="combobox"] { background:var(--soft)!important; color:var(--text)!important; border-color:var(--line)!important; }
[data-testid="stMultiSelect"] input { background:transparent!important; color:var(--text)!important; }
[data-testid="stMultiSelect"] button { color:var(--muted); }
[role="listbox"] { background:var(--panel)!important; color:var(--text)!important; border-color:var(--line)!important; }
[role="option"] { color:var(--text)!important; }
[role="option"][data-focused] { background:var(--tint)!important; }
[data-testid="stVegaLiteChart"] { direction:ltr; }
[data-testid="stAlertContainer"] { background:var(--tint)!important; color:var(--text)!important; border:1px solid var(--line); border-radius:12px; }
[data-testid="stAlertContainer"] p { color:var(--text)!important; }
"""

def apply_theme() -> None:
    palette = PALETTES[st.session_state.get("dark_mode", False)]
    variables = ";".join(f"--{key}:{value}" for key, value in palette.items())
    styles = DASHBOARD_STYLES
    st.markdown(f"<style>:root{{{variables}}}{styles}</style>", unsafe_allow_html=True)


def show_dataframe(data, **kwargs):
    palette = PALETTES[st.session_state.get("dark_mode", False)]
    styled = data.style.set_properties(color=palette["text"]) if isinstance(data, pd.DataFrame) else data
    styled = styled.set_properties(**{"background-color": palette["panel"]})
    return st.dataframe(styled, **kwargs)


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


LOGIN_EVENT_TYPES = {"login", "logon", "sign in", "تسجيل دخول", "محاولة دخول", "دخول"}
LOGIN_FAILURE_TYPES = {
    "login failure", "login failed", "failed login", "unsuccessful login",
    "logon failure", "logon failed", "failed logon", "sign in failure", "sign in failed",
    "فشل تسجيل الدخول", "فشل تسجيل دخول", "فشل دخول", "دخول فاشل",
    "تسجيل دخول فاشل", "محاولة دخول فاشلة",
}
LOGIN_SUCCESS_TYPES = {
    "login success", "login successful", "successful login", "login succeeded",
    "logon success", "successful logon", "sign in success", "successful sign in",
    "نجاح تسجيل الدخول", "نجاح تسجيل دخول", "نجاح دخول", "دخول ناجح", "تسجيل دخول ناجح",
}
FAILURE_OUTCOMES = {"failure", "failed", "fail", "فشل", "فاشل"}
SUCCESS_OUTCOMES = {"success", "successful", "succeeded", "نجاح", "ناجح"}
UPLOAD_IDENTITY_COLUMNS = ["source_ip", "target", "target_account"]


def normalized_alert_type(value: str) -> str:
    return " ".join(value.casefold().replace("-", " ").replace("_", " ").split())


def classify_outcome(row: pd.Series) -> str:
    """Use an explicit outcome, or infer it from a recognized login label."""
    explicit = str(row.get("event_outcome", "") or "").strip().lower()
    if explicit:
        if explicit in FAILURE_OUTCOMES:
            return "failure"
        if explicit in SUCCESS_OUTCOMES:
            return "success"
        return "other"

    description = normalized_alert_type(str(row.get("alert_type", "")))
    if description in LOGIN_FAILURE_TYPES:
        return "failure"
    if description in LOGIN_SUCCESS_TYPES:
        return "success"
    return "other"


def has_failure_then_success(group: pd.DataFrame) -> bool:
    outcomes = group.apply(classify_outcome, axis=1)
    failures = outcomes.eq("failure")
    successes = outcomes.eq("success")
    if not failures.any() or not successes.any():
        return False
    return group.loc[successes, "alert_time"].max() > group.loc[failures, "alert_time"].min()


def case_windows(data: pd.DataFrame, columns: list[str]):
    for key, related in data.groupby(columns, dropna=False, sort=False):
        window = fixed_five_minute_windows(related["alert_time"])
        for _, group in related.groupby(window):
            yield key, group


def previous_upload_ids(data: pd.DataFrame, dataset_id: str) -> dict[frozenset, list[str]]:
    """Rebuild prior file-scoped cases and keep only unambiguous identities."""
    # Reproduce the event families used by e42a98c for saved IDs.
    old_login_words = ("login", "logon", "sign-in", "sign in", "تسجيل دخول", "محاولة دخول")
    old_text = (data["alert_type"] + " " + data["detection_rule"]).str.lower()
    old_login = old_text.map(lambda value: any(word in value for word in old_login_words))
    old_families = (data["alert_type"] + "|" + data["detection_rule"]).mask(old_login, "__login__")
    # e5428bc grouped across families, and e42a98c split the same windows by family.
    versions = (
        (data, UPLOAD_IDENTITY_COLUMNS),
        (data.assign(_old_family=old_families), UPLOAD_IDENTITY_COLUMNS + ["_old_family"]),
    )

    by_id: dict[str, set[frozenset]] = {}
    for version, columns in versions:
        for key, group in case_windows(version, columns):
            start = group["alert_time"].iloc[0].isoformat()
            parts = (dataset_id, *key[:3], start)
            if len(key) == 4 and key[3] != "__login__":
                parts += (key[3],)
            case_id = "csv-" + stable_case_id(parts)
            by_id.setdefault(case_id, set()).add(frozenset(group.index))

    by_members: dict[frozenset, list[str]] = {}
    for case_id, memberships in by_id.items():
        if len(memberships) == 1:
            members = next(iter(memberships))
            by_members.setdefault(members, []).append(case_id)
    return by_members


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
                         "previous_case_id": previous_case_id, "previous_case_ids": [previous_case_id], "source": source})
    else:
        # Exact duplicate rows are one event. Separate attempts are preserved as evidence.
        data = data.drop_duplicates(subset=ALL_COLUMNS).sort_values("alert_time", kind="stable").reset_index(drop=True)
        legacy_ids = previous_upload_ids(data, dataset_id)
        login_types = LOGIN_EVENT_TYPES | LOGIN_FAILURE_TYPES | LOGIN_SUCCESS_TYPES
        data["_is_login"] = data["alert_type"].map(normalized_alert_type).isin(login_types)
        data["_family_type"] = data["alert_type"].mask(data["_is_login"], "")
        data["_family_rule"] = data["detection_rule"].mask(data["_is_login"], "")
        family_columns = ["_is_login", "_family_type", "_family_rule"]
        for key, group in case_windows(data, UPLOAD_IDENTITY_COLUMNS + family_columns):
            severity_label, severity_value = highest_severity(group)
            count = len(group)
            burst_bonus = 2 if count >= 10 else 1 if count >= 3 else 0
            success_after_failure = bool(key[2] and key[3] and has_failure_then_success(group))
            level = min(4, severity_value + burst_bonus + int(success_after_failure))
            case_parts = (dataset_id, *key, group["alert_time"].iloc[0].isoformat())
            case_id = "csv-v3-" + stable_case_id((json.dumps(case_parts, ensure_ascii=False),))
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
            evidence[case_id] = group.drop(columns=family_columns).copy()
            rows.append({"case_id": case_id, "first_time": group["alert_time"].min(),
                         "last_time": group["alert_time"].max(), "alert_type": alert_types,
                         "source_ip": key[0], "target": key[1], "target_account": key[2],
                         "severity": severity_label, "priority_level": level,
                         "priority": PRIORITY_LABELS[level], "reason": reason, "event_count": count,
                         "detection_rule": detection_rules,
                         "previous_case_id": "", "previous_case_ids": legacy_ids.get(frozenset(group.index), []), "source": source})
    cases = sort_cases(pd.DataFrame(rows))
    return cases.reset_index(drop=True), evidence


def attach_investigations(cases: pd.DataFrame) -> pd.DataFrame:
    if cases.empty:
        return cases
    investigations = load_investigations().rename(columns={"case_id": "saved_case_id"})
    candidates = cases[["case_id"]].assign(saved_case_id=cases["case_id"], is_current=True)
    aliases = (
        cases[["case_id", "previous_case_ids"]]
        .explode("previous_case_ids")
        .rename(columns={"previous_case_ids": "saved_case_id"})
    )
    candidates = pd.concat([candidates, aliases.assign(is_current=False)], ignore_index=True)
    saved = candidates.merge(investigations, on="saved_case_id", how="inner")
    saved["timestamp"] = pd.to_datetime(saved["updated_at"], format="mixed", errors="coerce", utc=True)
    latest = saved.sort_values(["timestamp", "is_current"], ascending=False).drop_duplicates("case_id")
    merged = cases.merge(latest[["case_id", "status", "verdict", "notes", "updated_at"]], on="case_id", how="left")
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
        show_dataframe(problems, use_container_width=True, hide_index=True)
        return None, "demo"
    col1, col2, col3 = st.columns(3)
    col1.metric("إجمالي الصفوف", len(valid) + len(problems))
    col2.metric("صفوف مقبولة", len(valid))
    col3.metric("تحتاج تصحيحًا", len(problems))
    st.markdown("#### معاينة الصفوف المقبولة")
    show_dataframe(valid.head(20), use_container_width=True, hide_index=True)
    if not problems.empty:
        with st.expander("الصفوف التي تحتاج تصحيحًا", expanded=True):
            show_dataframe(problems, use_container_width=True, hide_index=True)
    if valid.empty:
        st.warning("لا توجد صفوف صالحة للتحليل.")
        return None, "demo"
    if st.button("تحليل الصفوف المقبولة", type="primary", use_container_width=True):
        progress = st.progress(20, text="التحقق من الحقول وجودة البيانات…")
        progress.progress(55, text="تجميع الأحداث في حالات مترابطة…")
        st.session_state["uploaded_events"] = valid
        st.session_state["upload_id"] = fingerprint
        progress.progress(85, text="حساب الأولوية وتجهيز قائمة المراجعة…")
        st.session_state["data_source"] = "upload"
        progress.progress(100, text="اكتمل التحليل بنجاح")
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
    total = len(cases)
    closed = int(cases["status"].eq("مغلقة").sum())
    urgent = int(cases["priority"].eq("عاجلة").sum())
    investigating = int(cases["status"].eq("قيد التحقيق").sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("إجمالي الحالات", f"{total:,}")
    c2.metric("حالات عاجلة", f"{urgent:,}")
    c3.metric("قيد التحقيق", f"{investigating:,}")
    c4.metric("حالات مغلقة", f"{closed:,}")

    palette = PALETTES[st.session_state.get("dark_mode", False)]
    chart_config = {
        "background": "transparent", "view": {"stroke": None},
        "axis": {"labelColor": palette["muted"], "titleColor": palette["muted"],
                 "gridColor": palette["line"], "domain": False, "ticks": False,
                 "labelFont": "IBM Plex Sans Arabic", "labelPadding": 10},
    }
    trend, priorities = st.columns([1.35, 1], gap="medium")
    with trend, st.container(border=True, key="trend-panel"):
        st.markdown("#### حركة التنبيهات")
        st.caption("عدد الأحداث عبر الوقت")
        if cases["last_time"].notna().any():
            visible_ids = set(cases["case_id"])
            events = pd.concat([frame for cid, frame in evidence.items() if cid in visible_ids], ignore_index=True)
            timeline = events.set_index("alert_time").resample("h").size().rename("count").reset_index()
            st.vega_lite_chart(timeline, {
                "height": 180, "config": chart_config,
                "mark": {"type": "bar", "color": "#228455", "cornerRadiusTopLeft": 8, "cornerRadiusTopRight": 8, "size": 28},
                "encoding": {"x": {"field": "alert_time", "type": "temporal", "title": None, "axis": {"format": "%H:%M"}},
                             "y": {"field": "count", "type": "quantitative", "title": None},
                             "tooltip": [{"field": "alert_time", "type": "temporal", "title": "الوقت"}, {"field": "count", "title": "التنبيهات"}]},
            }, use_container_width=True)
        else:
            st.markdown('<div class="empty-chart"><span>◷</span><strong>بانتظار البيانات الزمنية</strong>'
                        '<p>ارفعي ملف تنبيهات يحتوي أوقات الأحداث لعرض نشاطها هنا.</p></div>', unsafe_allow_html=True)
    with priorities, st.container(border=True, key="priority-panel"):
        st.markdown("#### أولوية المراجعة")
        st.caption("توزيع الحالات حسب الأولوية")
        priority_order = ["عاجلة", "عالية", "متوسطة", "منخفضة"]
        distribution = cases["priority"].value_counts().reindex(priority_order, fill_value=0).rename_axis("priority").reset_index(name="count")
        st.vega_lite_chart(distribution, {
            "height": 180, "config": chart_config,
            "mark": {"type": "bar", "cornerRadiusEnd": 6, "height": 19},
            "encoding": {"y": {"field": "priority", "type": "nominal", "sort": priority_order, "title": None},
                         "x": {"field": "count", "type": "quantitative", "title": None},
                         "color": {"field": "priority", "type": "nominal", "legend": None,
                                   "scale": {"domain": priority_order, "range": ["#A5473F", "#B77B32", "#268052", "#88B89C"]}},
                         "tooltip": [{"field": "priority", "title": "الأولوية"}, {"field": "count", "title": "عدد الحالات"}]},
        }, use_container_width=True)

    activity, completion = st.columns([1.35, 1], gap="medium")
    with activity, st.container(border=True, key="activity-panel"):
        st.markdown("#### حالات تستحق المراجعة")
        st.caption("أول أربع حالات وفق الترتيب المختار")
        for row in cases.head(4).itertuples():
            tone = {"عاجلة": "urgent", "عالية": "high", "متوسطة": "medium", "منخفضة": "low"}[row.priority]
            st.markdown(
                f'<div class="activity-row"><div class="activity-icon">◎</div><div class="activity-info">'
                f'<strong>{html.escape(str(row.alert_type))}</strong><span class="ltr">{html.escape(str(row.source_ip))}</span>'
                f'</div><span class="badge {tone}">{row.priority}</span></div>', unsafe_allow_html=True,
            )
        if cases.empty:
            st.info("لا توجد حالات تطابق التصفية الحالية.")
    with completion, st.container(border=True, key="completion-panel"):
        percent = round(closed * 100 / total) if total else 0
        st.markdown("#### تقدم التحقيقات")
        st.caption("نسبة الحالات المغلقة ضمن النتائج المعروضة")
        st.markdown(
            f'<div class="progress-ring" style="--progress:{percent}%" role="img" aria-label="الحالات المغلقة {percent}%">'
            f'<div><strong>{percent}%</strong><span>اكتملت مراجعتها</span></div></div>'
            f'<div class="ring-legend"><span><i></i>مغلقة {closed:,}</span><span>مفتوحة {total - closed:,}</span></div>',
            unsafe_allow_html=True,
        )


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


def compact_case_panel(case: pd.Series, evidence: dict[str, pd.DataFrame]) -> None:
    """Render investigation details beside the selected alert row."""
    priority_color = {"عاجلة": "#FB7185", "عالية": "#FB923C", "متوسطة": "#FACC15", "منخفضة": "#2DD4BF"}.get(case["priority"], "#2DD4BF")
    priority = html.escape(str(case["priority"]))
    alert_type = html.escape(str(case["alert_type"]))
    reason = html.escape(str(case["reason"]))
    source_ip = html.escape(str(case["source_ip"]))
    target = html.escape(str(case["target"]))
    account = html.escape(str(case["target_account"] or "—"))
    st.markdown(
        f'<div class="case-panel"><div class="priority" style="color:{priority_color}">● {priority}</div>'
        f'<h3>{alert_type}</h3><p><strong>سبب الأولوية</strong><br>{reason}</p>'
        f'<p><strong>المصدر</strong> <span class="ltr">{source_ip}</span><br>'
        f'<strong>الهدف</strong> <span class="ltr">{target}</span><br>'
        f'<strong>الحساب</strong> <span class="ltr">{account}</span></p></div>',
        unsafe_allow_html=True,
    )
    raw = evidence.get(case["case_id"], pd.DataFrame()).copy()
    with st.expander(f"التسلسل الزمني · {len(raw):,} حدث", expanded=True):
        if "alert_time" in raw and raw["alert_time"].notna().any():
            timeline_columns = ["alert_time", "alert_type", "source_ip", "target", "event_outcome"]
            show_dataframe(raw[timeline_columns].sort_values("alert_time"), hide_index=True, use_container_width=True, height=220)
        elif not raw.empty:
            show_dataframe(raw.head(20), hide_index=True, use_container_width=True, height=220)
        else:
            st.caption("لا توجد أحداث تفصيلية لهذه الحالة.")
    with st.form(f"quick-investigation-{case['case_id']}"):
        status_index = STATUS_OPTIONS.index(case["status"]) if case["status"] in STATUS_OPTIONS else 0
        verdict_index = VERDICT_OPTIONS.index(case["verdict"]) if case["verdict"] in VERDICT_OPTIONS else 0
        status = st.selectbox("حالة التحقيق", STATUS_OPTIONS, index=status_index)
        verdict = st.selectbox("نتيجة المراجعة", VERDICT_OPTIONS, index=verdict_index)
        notes = st.text_area("الملاحظات", value=case["notes"], height=105)
        if st.form_submit_button("حفظ التحقيق", type="primary", use_container_width=True):
            save_investigation(case["case_id"], status, verdict, notes)
            st.success("حُفظ التحقيق.")
            st.rerun()


def alerts_table(cases: pd.DataFrame, evidence: dict[str, pd.DataFrame]) -> None:
    st.subheader("قائمة التنبيهات والحالات")
    table = cases[["last_time", "alert_type", "source_ip", "target", "severity", "priority", "status", "event_count", "case_id"]].copy()
    table.columns = ["الوقت", "نوع التنبيه", "عنوان المصدر", "الهدف", "الخطورة", "أولوية المراجعة", "حالة التحقيق", "عدد الأحداث", "معرّف الحالة"]
    st.caption(f"يعرض الجدول {len(table):,} حالة. الترتيب الافتراضي يبدأ بالأولوية الأعلى.")
    priority_colors = {"عاجلة": "#C8665C", "عالية": "#B98739", "متوسطة": "#32865A", "منخفضة": "#73A88B"}
    status_colors = {"جديدة": "#8B5CF6", "قيد التحقيق": "#2DD4BF", "مصعّدة": "#FB923C", "مغلقة": "#64748B"}
    def color_badges(value):
        color = priority_colors.get(str(value), status_colors.get(str(value)))
        return f"color:{color};font-weight:700" if color else ""
    palette = PALETTES[st.session_state.get("dark_mode", False)]
    styled = table.style.set_properties(color=palette["text"]).map(color_badges, subset=["أولوية المراجعة", "حالة التحقيق"])
    table_area, details_area = st.columns([2.15, 1], gap="large")
    with table_area:
        selection = show_dataframe(
            styled, use_container_width=True, hide_index=True, height=560,
            on_select="rerun", selection_mode="single-row", key="alerts-table",
        )
        st.download_button("⬇️ تصدير النتائج", safe_export_csv(cases),
                           "triage_cases.csv", "text/csv", use_container_width=True)
    with details_area:
        selected_rows = selection.selection.rows
        if selected_rows:
            compact_case_panel(cases.reset_index(drop=True).iloc[selected_rows[0]], evidence)
        else:
            st.info("اختاري صفًا من جدول التنبيهات لعرض تفاصيل الحالة وبدء التحقيق.")


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
            show_dataframe(timeline.sort_values("alert_time"), use_container_width=True, hide_index=True)
        else:
            st.caption("البيانات الأصلية لا توفر طابعًا زمنيًا في قائمة الأولوية المحفوظة.")
            show_dataframe(raw, use_container_width=True, hide_index=True)
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
        show_dataframe(scorecard[["القاعدة", "عدد التنبيهات", "الدقة", "نسبة الهجمات المكتشفة"]],
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
        show_dataframe(grouped, use_container_width=True, hide_index=True)
        st.caption("لا يحتوي الملف المرفوع تصنيفًا مرجعيًا؛ لذلك تعرض الصفحة الحجم ونتائج المراجعة المسجّلة فقط.")


def main() -> None:
    if "data_source" not in st.session_state:
        st.session_state["data_source"] = "demo"

    st.sidebar.markdown(
        '<div class="side-brand"><div class="brand-symbol">◎</div><div><strong>مرصد</strong>'
        '<small>مركز العمليات الأمنية</small></div></div><div class="nav-label">مساحة العمل</div>',
        unsafe_allow_html=True,
    )
    section = st.sidebar.radio("التنقل", ["نظرة عامة", "التنبيهات", "التحقيقات", "أداء الكشف"], label_visibility="collapsed")
    st.sidebar.toggle("الوضع الداكن", key="dark_mode", value=False)
    apply_theme()

    source_name = "priority_queue.csv" if st.session_state["data_source"] == "demo" else "الملف المرفوع"
    last_analysis = pd.Timestamp.now(tz="Asia/Riyadh").strftime("%H:%M، %d/%m/%Y")
    st.markdown(
        f'<div class="hero"><div><div class="eyebrow">مساحة المراقبة والتحقيق</div><h1>نظرة على المشهد الأمني</h1>'
        f'<p>الملف الجاري تحليله: <span class="ltr">{source_name}</span> · وقت العرض: {last_analysis}</p></div></div>',
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
        alerts_table(filtered, evidence)
    elif section == "التحقيقات":
        case_details(filtered, evidence)
    else:
        rule_performance(filtered, source)


if __name__ == "__main__":
    main()
