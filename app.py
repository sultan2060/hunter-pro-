import streamlit as st
from monitor_view import (
    monitor_prepare,
    monitor_requested,
    monitor_open_button,
    render_monitor,
)
import pandas as pd
import numpy as np
import yfinance as yf
import pandas_market_calendars as mcal
import plotly.graph_objects as go
import textwrap
import html
import requests
import re

from zoneinfo import ZoneInfo
from streamlit_autorefresh import st_autorefresh


# HUNTER access layer. Included in App.py; no separate module is required.
import hashlib
import hmac
import json
import math
import os
import secrets as secure_random
import sqlite3
import time
import threading
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HUNTER_VERSION = "2026.09.14-public"
HUNTER_TFS = ["1m", "3m", "5m", "10m", "15m", "30m", "45m", "1H", "2H", "4H", "6H", "8H", "Daily", "Weekly", "Monthly"]
HUNTER_WEIGHTS = {"1m": .5, "3m": 1., "5m": 1.5, "10m": 1.25, "15m": 1.5,
                  "30m": 1.5, "45m": 1., "1H": 1.5, "2H": 1., "4H": 1.,
                  "6H": .5, "8H": .5, "Daily": 1., "Weekly": .5, "Monthly": .25}
HUNTER_ACTIVE_STATES = {"LIVE", "PRE-MARKET", "POST-MARKET"}
HUNTER_LAUNCH_WEIGHTS = {"1m": 1., "3m": 1.25, "5m": 1.50, "15m": 1.25}
HUNTER_DEFAULTS = {
    "language": "العربية", "chart_timeframe": "1m", "target_timeframe": "5m",
    "candle_focus_timeframe": "5m", "candles_to_show": 60,
    "refresh_seconds": 15, "frame_weights": HUNTER_WEIGHTS,
    "launch_weights": HUNTER_LAUNCH_WEIGHTS,
}


def hunter_validate_settings(value):
    if not isinstance(value, dict) or set(value) != set(HUNTER_DEFAULTS):
        raise ValueError("ملف الإعدادات غير متوافق / Invalid settings file")
    result = json.loads(json.dumps(value, allow_nan=False))
    for field in ("chart_timeframe", "target_timeframe", "candle_focus_timeframe"):
        if result[field] == "60m":
            result[field] = "1H"
    old = result.get("frame_weights")
    if isinstance(old, dict) and set(old) != set(HUNTER_WEIGHTS):
        legacy = {"1m", "2m", "3m", "4m", "5m", "6m", "10m", "15m", "30m", "60m", "1H", "2H", "3H", "4H", "Daily", "Weekly"}
        if set(old) == legacy:
            # Keep owner-disabled weights disabled; new horizons start disabled on migration.
            result["frame_weights"] = {tf: old.get(tf, 0.) for tf in HUNTER_WEIGHTS}
    choices = {
        "language": ["العربية", "English"], "chart_timeframe": HUNTER_TFS,
        "target_timeframe": HUNTER_TFS,
        "candle_focus_timeframe": HUNTER_TFS,
        "candles_to_show": [40, 60, 100, 150],
        "refresh_seconds": [15, 30, 60],
    }
    for key, allowed in choices.items():
        if result[key] not in allowed or isinstance(result[key], bool):
            raise ValueError("قيمة إعداد غير صالحة: " + key)
    for key, template in [("frame_weights", HUNTER_WEIGHTS),
                          ("launch_weights", HUNTER_LAUNCH_WEIGHTS)]:
        weights = result[key]
        if not isinstance(weights, dict) or set(weights) != set(template):
            raise ValueError("الفريمات في ملف الأوزان غير صحيحة")
        for weight in weights.values():
            if (isinstance(weight, bool) or not isinstance(weight, (int, float))
                    or not math.isfinite(weight) or not 0 <= weight <= 10):
                raise ValueError("الأوزان يجب أن تكون بين صفر و10")
        if sum(weights.values()) <= 0:
            raise ValueError("يجب تفعيل وزن واحد على الأقل")
    return result


def hunter_password_hash(password, salt=None):
    salt = salt or secure_random.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000)
    return "pbkdf2_sha256$600000$" + salt + "$" + digest.hex()


def hunter_valid_hash(encoded):
    try:
        algorithm, iterations, salt, digest = encoded.split("$")
        return (algorithm == "pbkdf2_sha256" and iterations == "600000"
                and len(bytes.fromhex(salt)) == 16 and len(bytes.fromhex(digest)) == 32)
    except (AttributeError, ValueError, TypeError):
        return False


def hunter_check_password(password, encoded):
    if not hunter_valid_hash(encoded) or len(password) > 1024:
        return False
    return hmac.compare_digest(hunter_password_hash(password, encoded.split("$")[2]), encoded)


def hunter_accounts():
    try:
        accounts = {name: dict(value) for name, value in st.secrets["hunter"]["accounts"].items()}
    except (KeyError, FileNotFoundError):
        return {}
    for name, value in accounts.items():
        if (not isinstance(name, str) or not name or len(name) > 64
                or value.get("role") not in ("admin", "viewer")
                or not hunter_valid_hash(value.get("password_hash"))):
            return {}
    return accounts if any(a["role"] == "admin" for a in accounts.values()) else {}


def hunter_fingerprint(account):
    return hashlib.sha256((account["role"] + account["password_hash"]).encode()).hexdigest()


def hunter_identity():
    session = st.session_state.get("_hunter_identity", {})
    account = hunter_accounts().get(session.get("username"))
    if (not account or time.time() >= session.get("expires", 0)
            or not hmac.compare_digest(session.get("fingerprint", ""), hunter_fingerprint(account))):
        return None
    # Role comes from server secrets on EVERY rerun; never from a widget or URL.
    return {"username": session["username"], "role": account["role"]}


def hunter_require_user():
    identity = hunter_identity()
    if identity is not None:
        return identity
    # Explicit public read-only role; no URL, widget or session role can grant ownership.
    return {"username":"__public__", "role":"viewer", "public":True}


def hunter_require_admin():
    identity = hunter_require_user()
    if identity["role"] != "admin":
        raise PermissionError("Owner access required")
    return identity


def hunter_database():
    # Set HUNTER_DATA_DIR to a durable volume on independent hosting.
    directory = Path(os.environ.get("HUNTER_DATA_DIR", str(Path(__file__).parent / ".hunter_data")))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(directory / "hunter.sqlite3", timeout=10)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS preferences (username TEXT PRIMARY KEY, theme TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts (username TEXT PRIMARY KEY, failures INTEGER NOT NULL, blocked_until REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (ts REAL NOT NULL, username TEXT NOT NULL, action TEXT NOT NULL);
    """)
    return connection


def hunter_authenticate(username, password):
    username = username.strip()[:64]
    accounts = hunter_accounts()
    account = accounts.get(username)
    # Unknown users still incur a normal password hash; error messages are generic.
    dummy = "pbkdf2_sha256$600000$" + "0" * 32 + "$" + "0" * 64
    db = hunter_database()
    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT failures, blocked_until FROM attempts WHERE username=?", (username,)).fetchone()
        now = time.time()
        if row and row[1] > now:
            return False
        valid = hunter_check_password(password, account["password_hash"] if account else dummy)
        if valid and account:
            db.execute("DELETE FROM attempts WHERE username=?", (username,))
            db.execute("INSERT INTO audit VALUES (?, ?, ?)", (now, username, "login"))
            db.commit()
            st.session_state.clear()  # No prior account's state survives a new login.
            st.session_state["_hunter_identity"] = {
                "username": username, "fingerprint": hunter_fingerprint(account),
                "expires": now + 8 * 60 * 60,
            }
            return True
        failures = (row[0] if row and row[1] == 0 else 0) + 1
        blocked_until = now + 300 if failures >= 5 else 0
        # Track known accounts only, preventing arbitrary username rows.
        if account:
            db.execute("INSERT OR REPLACE INTO attempts VALUES (?, ?, ?)", (username, failures, blocked_until))
        db.commit()
        return False
    finally:
        db.close()


def hunter_login():
    # Opening the app never requires credentials. Optional owner authentication is separate.
    return hunter_require_user()


def hunter_load_settings():
    hunter_require_user()
    db = hunter_database()
    try:
        row = db.execute("SELECT value FROM settings WHERE id=1").fetchone()
    finally:
        db.close()
    return hunter_validate_settings(json.loads(row[0]) if row else HUNTER_DEFAULTS)


def hunter_save_settings(value):
    identity = hunter_require_admin()  # Server-side authorization precedes every write.
    value = hunter_validate_settings(value)
    db = hunter_database()
    try:
        with db:
            db.execute("INSERT OR REPLACE INTO settings VALUES (1, ?)", (json.dumps(value, ensure_ascii=False),))
            db.execute("INSERT INTO audit VALUES (?, ?, ?)", (time.time(), identity["username"], "save_settings"))
    finally:
        db.close()


def hunter_load_theme():
    identity = hunter_require_user()
    if identity.get("public"):
        return st.session_state.get("hunter_guest_theme", "light")
    db = hunter_database()
    try:
        row = db.execute("SELECT theme FROM preferences WHERE username=?", (identity["username"],)).fetchone()
    finally:
        db.close()
    return row[0] if row and row[0] in ("light", "dark") else "light"


def hunter_save_theme(theme):
    identity = hunter_require_user()
    if theme not in ("light", "dark"):
        raise ValueError("Invalid theme")
    if identity.get("public"):
        # Guest preferences stay in this visitor's session, never a shared guest database row.
        st.session_state["hunter_guest_theme"] = theme
        return
    db = hunter_database()
    try:
        with db:
            db.execute("INSERT OR REPLACE INTO preferences VALUES (?, ?)", (identity["username"], theme))
    finally:
        db.close()


def hunter_apply_theme(theme):
    dark = theme == "dark"
    background, panel, foreground, muted = (
        ("#0e1524", "#192538", "#eef4ff", "#a9b8d0") if dark
        else ("#ffffff", "#f1f4f8", "#14213a", "#5b667a")
    )
    st.markdown(f"""<style>
      .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {{
        background: {background}; color: {foreground}; color-scheme: {'dark' if dark else 'light'};
        --text-color: {foreground}; --background-color: {background};
        --secondary-background-color: {panel};
      }}
      [data-testid="stSidebar"], [data-testid="stForm"], [data-testid="stExpander"] {{background: {panel};}}
      .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5,
      .stApp label, [data-testid="stMarkdownContainer"], [data-testid="stMetricValue"],
      [data-testid="stMetricLabel"], .stTabs button {{color: {foreground};}}
      [data-testid="stCaptionContainer"], .qt-sub {{color: {muted};}}
      .stApp input, .stApp [data-baseweb="select"] > div,
      .stApp [data-baseweb="input"], .stApp [data-baseweb="base-input"],
      .stApp button[kind="secondary"] {{background-color: {panel}; color: {foreground};}}
      [data-baseweb="popover"] ul, [data-baseweb="popover"] li {{background-color: {panel}; color: {foreground};}}
      .stApp [data-testid="stMetric"], .qt-action {{background-color: {panel}; color: {foreground};}}
    </style>""", unsafe_allow_html=True)


def hunter_dataframe(data, **kwargs):
    # Style the table cells too; CSS alone cannot recolor Streamlit's canvas tables.
    if isinstance(data, pd.DataFrame):
        dark = st.session_state.get("hunter_theme") == "dark"
        data = data.style.format(precision=2).set_properties(**{
            "background-color": "#192538" if dark else "#ffffff",
            "color": "#eef4ff" if dark else "#14213a",
        })
    return st.dataframe(data, **kwargs)


def hunter_account_bar():
    identity = hunter_require_user()
    if "hunter_theme" not in st.session_state:
        st.session_state["hunter_theme"] = hunter_load_theme()
    left, right = st.columns([4,1])
    with left:
        theme = st.radio("المظهر / Appearance", ["light","dark"],
                         format_func=lambda value: "فاتح / Light" if value=="light" else "غامق / Dark",
                         horizontal=True, key="hunter_theme")
        if theme != hunter_load_theme():
            hunter_save_theme(theme)
    with right:
        if not identity.get("public"):
            if st.button("خروج المالك / Sign out", key="hunter_logout"):
                st.session_state.clear()
                st.rerun()
        elif hunter_accounts():
            with st.popover("إدارة المالك / Owner"):
                with st.form("hunter_owner_login", clear_on_submit=True):
                    username=st.text_input("اسم المالك / Owner username", max_chars=64)
                    password=st.text_input("كلمة مرور المالك / Owner password",type="password",max_chars=1024)
                    submitted=st.form_submit_button("دخول المالك / Owner sign in")
                if submitted:
                    if hunter_authenticate(username,password):
                        st.rerun()
                    st.error("تعذر تسجيل الدخول. / Sign-in failed.")
    hunter_apply_theme(theme)


def hunter_admin_panel(settings):
    if hunter_require_user()["role"] != "admin":
        return False
    hunter_require_admin()
    editing = st.toggle("فتح إعدادات المالك / Owner settings", value=False, key="hunter_editing")
    if not editing:
        return False
    st.caption("يتوقف التحديث التلقائي أثناء تحرير الإعدادات. الإعدادات المحفوظة تطبق على الحسابين.")
    st.info("الحفظ هنا محلي بالخادم. على Streamlit Cloud احتفظ بنسخة JSON؛ قد تحتاج استعادتها بعد إعادة النشر. للحفظ الدائم استخدم مساحة تخزين دائمة.")
    with st.form("hunter_settings"):
        choices = {
            "language": ("لغة الواجهة", ["العربية", "English"]),
            "target_timeframe": ("فريم التحليل الافتراضي للجلسات الجديدة", HUNTER_TFS),
            "candles_to_show": ("عدد الشموع المعروضة", [40, 60, 100, 150]),
            "refresh_seconds": ("تحديث الصفحة بالثواني", [15, 30, 60]),
        }
        updated = json.loads(json.dumps(settings))
        columns = st.columns(3)
        for i, (key, (label, options)) in enumerate(choices.items()):
            with columns[i % 3]:
                updated[key] = st.selectbox(label, options, index=options.index(settings[key]), key="owner_" + key)
        for key, label in [("frame_weights", "أوزان الفريمات"), ("launch_weights", "أوزان الانطلاقة")]:
            st.markdown("**" + label + "**")
            updated[key] = {}
            columns = st.columns(4)
            for i, (tf, weight) in enumerate(settings[key].items()):
                with columns[i % 4]:
                    updated[key][tf] = st.number_input(tf, min_value=0., max_value=10., value=float(weight),
                                                       step=.25, key="owner_" + key + tf)
        submitted = st.form_submit_button("حفظ إعدادات البرنامج", width="stretch")
    if submitted:
        try:
            hunter_save_settings(updated)
        except ValueError as error:
            st.error(str(error))
        else:
            st.success("تم الحفظ. حمّل النسخة الاحتياطية المحدثة أدناه.")
            settings = updated
    hunter_require_admin()
    st.download_button("تنزيل نسخة الإعدادات JSON", json.dumps(settings, ensure_ascii=False, indent=2),
                       file_name="hunter-settings.json", mime="application/json", key="owner_backup")
    restore = st.file_uploader("استعادة نسخة إعدادات JSON", type=["json"], key="owner_restore_file")
    if st.button("تطبيق النسخة المستعادة", disabled=restore is None, key="owner_restore"):
        hunter_require_admin()
        try:
            if restore.size > 65536:
                raise ValueError("ملف الإعدادات أكبر من الحد المسموح")
            hunter_save_settings(json.loads(restore.getvalue()))
        except (ValueError, UnicodeDecodeError) as error:
            st.error("تعذر استعادة الإعدادات: " + str(error))
        else:
            for key in list(st.session_state):
                if key.startswith("owner_"):
                    del st.session_state[key]
            st.rerun()
    st.caption("إدارة أسماء الحسابات وكلمات المرور وصلاحياتها متاحة للمالك عبر إعدادات Secrets للاستضافة. لا تُعرض بيانات الدخول داخل التطبيق.")
    return True


# ============================================================
# APP CONFIG
# ============================================================

APP_NAME = "HUNTER · WAVE ENGINE"
APP_SUBTITLE = "Market Research & Paper Trading Console"

st.set_page_config(
    page_title=APP_NAME,
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="collapsed",
    menu_items={"Get Help": None, "Report a bug": None, "About": None},
)

# Hiding native chrome is cosmetic; role guards below enforce permissions.
st.markdown("""<style>
  #MainMenu, [data-testid="stToolbar"], [data-testid="stDecoration"],
  [data-testid="stStatusWidget"], .stDeployButton, footer {display:none !important;}
  [data-testid="manage-app-button"], [data-testid="stAppDeployButton"] {display:none !important;}
</style>""", unsafe_allow_html=True)
hunter_user = hunter_login()
monitor_prepare()
IS_ADMIN = hunter_user["role"] == "admin"
hunter_settings = hunter_load_settings()
PRICE_BOARD_REFRESH_SECONDS = hunter_settings["refresh_seconds"]

st.markdown(
    """
    <style>
    .block-container {
        max-width: 1500px;
        padding-top: 0.8rem;
        padding-bottom: 0.8rem;
        padding-left: 1rem;
        padding-right: 1rem;
    }

    h1, h2, h3, h4, h5 {
        margin-top: 0.15rem !important;
        margin-bottom: 0.30rem !important;
    }

    div[data-testid="stMetric"] {
        border: 1px solid rgba(128,128,128,0.22);
        border-radius: 12px;
        padding: 0.50rem 0.65rem;
        min-height: 78px;
    }

    div[data-testid="stMetricLabel"] {
        font-size: 0.76rem;
    }

    div[data-testid="stMetricValue"] {
        font-size: 1.45rem;
    }

    .qt-header {
        display:flex;
        align-items:end;
        justify-content:space-between;
        gap:12px;
        flex-wrap:wrap;
        margin-bottom:0.35rem;
    }

    .qt-brand {
        font-size:1.7rem;
        font-weight:800;
        letter-spacing:0.03em;
    }

    .qt-sub {
        opacity:0.68;
        font-size:0.82rem;
    }

    .qt-badge {
        display:inline-block;
        padding:0.22rem 0.52rem;
        border-radius:999px;
        border:1px solid rgba(128,128,128,0.30);
        font-size:0.70rem;
        margin-right:0.20rem;
        margin-bottom:0.2rem;
    }

    .qt-action {
        border: 1px solid rgba(128,128,128,0.25);
        border-radius: 14px;
        padding: 0.85rem 1rem;
        margin: 0.30rem 0 0.55rem 0;
    }

    .qt-action-title {
        font-size: 1.35rem;
        font-weight: 800;
        margin-bottom: 0.20rem;
    }

    .qt-action-sub {
        font-size: 0.86rem;
        opacity: 0.78;
    }

    .qt-market-label {
        font-size: 0.74rem;
        font-weight: 800;
        letter-spacing: 0.04em;
        opacity: 0.82;
        margin-bottom: 0.22rem;
    }

    .qt-price-board {
        border: 2px solid rgba(120, 130, 150, 0.52);
        border-radius: 18px;
        padding: 0.85rem 1.05rem;
        margin: 0.45rem 0 0.65rem 0;
        background:
            linear-gradient(
                135deg,
                rgba(18, 23, 33, 0.98),
                rgba(30, 36, 49, 0.98)
            );
        color: #f8fafc;
        display: grid;
        grid-template-columns: minmax(150px, 0.8fr) minmax(260px, 1.5fr) minmax(180px, 0.9fr);
        gap: 1rem;
        align-items: center;
    }

    .qt-price-board.up {
        border-color: rgba(34, 197, 94, 0.88);
    }

    .qt-price-board.down {
        border-color: rgba(239, 68, 68, 0.88);
    }

    .qt-price-board.flat {
        border-color: rgba(148, 163, 184, 0.72);
    }

    .qt-price-symbol {
        font-size: 1.55rem;
        font-weight: 900;
        letter-spacing: 0.04em;
    }

    .qt-price-name {
        font-size: 0.78rem;
        opacity: 0.72;
        margin-top: 0.10rem;
    }

    .qt-price-main {
        font-variant-numeric: tabular-nums;
        font-size: clamp(2.35rem, 5.2vw, 4.8rem);
        line-height: 0.95;
        font-weight: 900;
        letter-spacing: 0.015em;
        white-space: nowrap;
    }

    .qt-price-change {
        font-variant-numeric: tabular-nums;
        font-size: 1.02rem;
        font-weight: 800;
        margin-top: 0.42rem;
    }

    .qt-price-change.up {
        color: #4ade80;
    }

    .qt-price-change.down {
        color: #fb7185;
    }

    .qt-price-change.flat {
        color: #cbd5e1;
    }

    .qt-price-meta {
        text-align: end;
        font-size: 0.78rem;
        line-height: 1.55;
        opacity: 0.84;
    }

    .qt-price-status {
        display: inline-block;
        border: 1px solid rgba(255,255,255,0.24);
        border-radius: 999px;
        padding: 0.18rem 0.48rem;
        margin-bottom: 0.28rem;
        font-weight: 800;
    }

    @media (prefers-reduced-motion: no-preference) {
        .qt-price-board.price-changed {
            animation: qtPricePulse 0.75s ease-out 1;
        }

        @keyframes qtPricePulse {
            0% { transform: scale(1); }
            42% { transform: scale(1.006); }
            100% { transform: scale(1); }
        }
    }

    .qt-news-strip {
        border: 1px solid rgba(128,128,128,0.28);
        border-radius: 14px;
        padding: 0.65rem 0.80rem;
        margin: 0.25rem 0 0.55rem 0;
        display: grid;
        grid-template-columns: minmax(120px, 0.35fr) minmax(0, 1.65fr);
        gap: 0.75rem;
        align-items: center;
    }

    .qt-news-strip.high {
        border-width: 2px;
        border-color: rgba(239, 68, 68, 0.88);
    }

    .qt-news-strip.medium {
        border-color: rgba(245, 158, 11, 0.78);
    }

    .qt-news-strip.low {
        border-color: rgba(148, 163, 184, 0.60);
    }

    .qt-news-kicker {
        font-size: 0.72rem;
        font-weight: 900;
        opacity: 0.80;
        letter-spacing: 0.04em;
    }

    .qt-news-headline {
        font-size: 0.92rem;
        font-weight: 800;
        line-height: 1.35;
        overflow-wrap: anywhere;
    }

    .qt-news-meta {
        font-size: 0.72rem;
        opacity: 0.72;
        margin-top: 0.18rem;
    }

    .qt-news-card {
        border: 1px solid rgba(128,128,128,0.24);
        border-radius: 12px;
        padding: 0.70rem 0.80rem;
        margin-bottom: 0.55rem;
    }

    .qt-news-title {
        font-weight: 800;
        line-height: 1.35;
        margin-bottom: 0.18rem;
    }

    .qt-news-badges {
        font-size: 0.70rem;
        opacity: 0.78;
        margin-bottom: 0.18rem;
    }

    .qt-news-summary {
        font-size: 0.78rem;
        opacity: 0.82;
        line-height: 1.45;
    }

    /* Public-share visual hardening */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header[data-testid="stHeader"] {background: transparent;}

    .qt-disclaimer {
        font-size:0.70rem;
        opacity:0.72;
        line-height:1.35;
        border-top:1px solid rgba(128,128,128,0.20);
        padding-top:0.50rem;
        margin-top:0.50rem;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap:0.30rem;
    }

    .stTabs [data-baseweb="tab"] {
        height:2.25rem;
        padding-left:0.65rem;
        padding-right:0.65rem;
    }

    @media (max-width: 768px) {
        .block-container {
            padding-left:0.50rem;
            padding-right:0.50rem;
            padding-top:0.35rem;
        }

        .qt-brand {
            font-size:1.30rem;
        }

        .qt-sub {
            font-size:0.70rem;
        }

        div[data-testid="stMetric"] {
            padding:0.38rem 0.45rem;
            min-height:68px;
        }

        div[data-testid="stMetricValue"] {
            font-size:1.12rem;
        }

        .qt-action-title {
            font-size:1.12rem;
        }

        .qt-price-board {
            grid-template-columns: 1fr;
            gap: 0.45rem;
            padding: 0.75rem 0.85rem;
        }

        .qt-price-main {
            font-size: clamp(2.55rem, 13vw, 4rem);
        }

        .qt-price-meta {
            text-align: start;
        }

        .qt-news-strip {
            grid-template-columns: 1fr;
            gap: 0.25rem;
        }

        .stTabs [data-baseweb="tab"] {
            font-size:0.75rem;
            padding-left:0.40rem;
            padding-right:0.40rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SYMBOLS / MARKET
# ============================================================

SYMBOLS = {
    "SPX": "^GSPC",
    "TSLA": "TSLA",
    "MSTR": "MSTR",
    "CRWD": "CRWD",
    "MU": "MU",
}

MARKET_NAMES = {
    "SPX": "S&P 500 Index",
    "TSLA": "Tesla",
    "MSTR": "MSTR",
    "CRWD": "CrowdStrike",
    "MU": "Micron Technology",
}

NY_TZ = ZoneInfo("America/New_York")
NYSE = mcal.get_calendar("NYSE")


# ============================================================
# DATA
# ============================================================

@st.cache_data(ttl=45)
def download_data(ticker, period, interval):
    try:
        df = yf.download(
            ticker,
            period=period,
            interval=interval,
            auto_adjust=False,
            progress=False,
            prepost=False,
            threads=False,
            multi_level_index=False,
        )

        if df is None or df.empty:
            return pd.DataFrame()

        df = df.copy()

        if isinstance(df.columns, pd.MultiIndex):
            df.columns = df.columns.get_level_values(0)

        required = ["Open", "High", "Low", "Close"]

        if any(col not in df.columns for col in required):
            return pd.DataFrame()

        if "Volume" not in df.columns:
            df["Volume"] = 0

        return df.dropna(subset=required)

    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=12)
def get_fast_quote(ticker):
    """
    Best-effort quick quote for the selected instrument.
    This is not an exchange-grade streaming feed.
    Falls back to the latest 1-minute bar when unavailable.
    """
    result = {
        "price": None,
        "previous_close": None,
        "source": "1m fallback",
    }

    try:
        fast_info = yf.Ticker(ticker).fast_info

        def _read_fast_info(name):
            try:
                return fast_info[name]
            except Exception:
                try:
                    return getattr(fast_info, name)
                except Exception:
                    return None

        last_price = _read_fast_info("last_price")
        previous_close = _read_fast_info("previous_close")

        if last_price is not None and np.isfinite(float(last_price)):
            result["price"] = float(last_price)
            result["source"] = "Quick quote"

        if (
            previous_close is not None
            and np.isfinite(float(previous_close))
        ):
            result["previous_close"] = float(previous_close)

    except Exception:
        pass

    return result



def render_html(markup):
    """
    Render HTML without Markdown treating leading spaces as a code block.
    """
    st.markdown(
        textwrap.dedent(markup).strip(),
        unsafe_allow_html=True,
    )


@st.cache_data(ttl=21600, show_spinner=False)
def translate_to_arabic(text_value):
    """
    Best-effort headline translation for Arabic UI.
    Uses Google's public translate endpoint with a short timeout.
    Falls back to the original text if the service is unavailable.
    """
    if not text_value:
        return ""

    try:
        response = requests.get(
            "https://translate.googleapis.com/translate_a/single",
            params={
                "client": "gtx",
                "sl": "auto",
                "tl": "ar",
                "dt": "t",
                "q": text_value,
            },
            timeout=4,
        )
        response.raise_for_status()
        payload = response.json()

        translated = "".join(
            part[0]
            for part in payload[0]
            if part and part[0]
        ).strip()

        return translated or text_value

    except Exception:
        return text_value


def arabic_news_brief(item, max_chars=180):
    """
    Arabic one-line bullet headline for the Arabic interface.
    """
    translated = translate_to_arabic(
        item.get("title", "")
    )

    translated = re.sub(
        r"\s+",
        " ",
        translated,
    ).strip()

    if len(translated) > max_chars:
        translated = translated[:max_chars].rstrip() + "…"

    return translated


NEWS_REFRESH_SECONDS = 60

HIGH_IMPACT_TERMS = {
    "earnings", "guidance", "forecast", "revenue", "profit", "loss",
    "sec", "investigation", "lawsuit", "court", "patent", "recall",
    "downgrade", "upgrade", "price target", "analyst", "acquisition",
    "merger", "buyout", "offering", "secondary", "bankruptcy",
    "ceo", "cfo", "resign", "fired", "layoff", "contract",
    "government", "tariff", "sanction", "ban", "approval",
    "fda", "cyberattack", "hack", "breach",
    "fed", "fomc", "powell", "inflation", "cpi", "ppi",
    "payroll", "jobs", "unemployment", "gdp", "rate cut",
    "rate hike", "interest rate", "treasury", "yield",
}

BULLISH_TERMS = {
    "beats", "beat estimates", "raises guidance", "upgrade", "upgraded",
    "record revenue", "record profit", "approval", "approved",
    "wins contract", "contract win", "partnership", "buyback",
    "strong demand", "surges", "jumps", "rally", "growth",
    "outperform", "bullish", "rate cut", "cuts rates",
}

BEARISH_TERMS = {
    "misses", "miss estimates", "cuts guidance", "downgrade", "downgraded",
    "investigation", "lawsuit", "recall", "layoff", "bankruptcy",
    "offering", "secondary offering", "breach", "hack", "cyberattack",
    "weak demand", "slumps", "falls", "drops", "selloff",
    "underperform", "bearish", "rate hike", "raises rates",
}

MARKET_WIDE_TERMS = {
    "fed", "fomc", "powell", "inflation", "cpi", "ppi", "jobs",
    "payroll", "unemployment", "gdp", "interest rate", "rate cut",
    "rate hike", "treasury", "yield", "tariff", "sanction", "war",
    "oil", "opec", "government shutdown", "election",
}

def _safe_timestamp(value):
    if value is None:
        return None

    try:
        if isinstance(value, (int, float, np.integer, np.floating)):
            ts = pd.to_datetime(value, unit="s", utc=True)
        else:
            ts = pd.to_datetime(value, utc=True)

        return ts.tz_convert(NY_TZ)
    except Exception:
        return None


def _extract_news_item(raw, scope):
    if not isinstance(raw, dict):
        return None

    content = raw.get("content")
    if not isinstance(content, dict):
        content = {}

    title = (
        raw.get("title")
        or content.get("title")
        or ""
    )

    summary = (
        raw.get("summary")
        or content.get("summary")
        or content.get("description")
        or ""
    )

    publisher = (
        raw.get("publisher")
        or content.get("provider", {}).get("displayName")
        if isinstance(content.get("provider"), dict)
        else raw.get("publisher")
    )

    publisher = publisher or ""

    published_raw = (
        raw.get("providerPublishTime")
        or raw.get("pubDate")
        or content.get("pubDate")
        or content.get("displayTime")
    )

    published = _safe_timestamp(
        published_raw
    )

    link = (
        raw.get("link")
        or raw.get("url")
        or content.get("canonicalUrl", {}).get("url")
        if isinstance(content.get("canonicalUrl"), dict)
        else raw.get("link") or raw.get("url")
    )

    if not link and isinstance(content.get("clickThroughUrl"), dict):
        link = content.get("clickThroughUrl", {}).get("url")

    related = (
        raw.get("relatedTickers")
        or content.get("relatedTickers")
        or []
    )

    if not title:
        return None

    return {
        "title": str(title).strip(),
        "summary": str(summary).strip(),
        "publisher": str(publisher).strip(),
        "published": published,
        "link": link or "",
        "related": related,
        "scope": scope,
    }


@st.cache_resource
def hunter_news_memory():
    return {"lock":threading.RLock(), "pool":ThreadPoolExecutor(max_workers=2), "items":{}}


def hunter_news_snapshot(ticker, limit=12, scope="SYMBOL"):
    """Fetch news off the rendering path so headlines cannot delay price targets."""
    memory = hunter_news_memory()
    key = (ticker,limit,scope)
    with memory["lock"]:
        item = memory["items"].setdefault(key, {"future":None,"data":[],"requested":0.})
        future = item["future"]
        if future is not None and future.done():
            try:
                item["data"] = future.result()
            except Exception:
                item["data"] = []
            item["future"] = None
        if item["future"] is None and time.time()-item["requested"] >= NEWS_REFRESH_SECONDS:
            item["requested"] = time.time()
            item["future"] = memory["pool"].submit(get_news_feed,ticker,limit,scope)
        return [dict(row) for row in item["data"]]


@st.cache_data(ttl=NEWS_REFRESH_SECONDS)
def get_news_feed(ticker, limit=12, scope="SYMBOL"):
    items = []

    try:
        raw_news = yf.Ticker(ticker).news or []
    except Exception:
        raw_news = []

    for raw in raw_news[: max(limit * 2, limit)]:
        item = _extract_news_item(
            raw,
            scope
        )

        if item is not None:
            items.append(item)

        if len(items) >= limit:
            break

    return items


def score_news_item(item, now_ny):
    text_value = (
        f"{item.get('title', '')} "
        f"{item.get('summary', '')}"
    ).lower()

    high_hits = sum(
        1 for term in HIGH_IMPACT_TERMS
        if term in text_value
    )

    bullish_hits = sum(
        1 for term in BULLISH_TERMS
        if term in text_value
    )

    bearish_hits = sum(
        1 for term in BEARISH_TERMS
        if term in text_value
    )

    market_hits = sum(
        1 for term in MARKET_WIDE_TERMS
        if term in text_value
    )

    published = item.get("published")

    if published is not None:
        age_minutes = max(
            0.0,
            (now_ny - published).total_seconds() / 60.0
        )
    else:
        age_minutes = None

    recency_points = 0

    if age_minutes is not None:
        if age_minutes <= 30:
            recency_points = 3
        elif age_minutes <= 120:
            recency_points = 2
        elif age_minutes <= 360:
            recency_points = 1

    impact_score = (
        high_hits * 2
        + market_hits
        + recency_points
    )

    if impact_score >= 5:
        impact = "HIGH"
    elif impact_score >= 2:
        impact = "MEDIUM"
    else:
        impact = "LOW"

    if bullish_hits > bearish_hits:
        bias = "BULLISH"
    elif bearish_hits > bullish_hits:
        bias = "BEARISH"
    else:
        bias = "NEUTRAL"

    result = item.copy()
    result.update({
        "impact": impact,
        "headline_bias": bias,
        "impact_score": impact_score,
        "age_minutes": age_minutes,
        "market_hits": market_hits,
    })

    return result


def merge_news(symbol_news, market_news, now_ny):
    scored = []

    for item in symbol_news + market_news:
        scored.append(
            score_news_item(
                item,
                now_ny
            )
        )

    # Remove duplicate headlines.
    unique = {}
    for item in scored:
        key = item["title"].strip().lower()
        current = unique.get(key)

        if current is None:
            unique[key] = item
        else:
            # Keep the higher-impact copy.
            if item["impact_score"] > current["impact_score"]:
                unique[key] = item

    impact_order = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def _sort_key(item):
        published = item.get("published")
        timestamp = (
            published.timestamp()
            if published is not None
            else 0
        )

        return (
            impact_order.get(item["impact"], 0),
            item["impact_score"],
            timestamp,
        )

    return sorted(
        unique.values(),
        key=_sort_key,
        reverse=True,
    )


def build_news_state(news_items):
    recent = [
        x for x in news_items
        if (
            x["age_minutes"] is None
            or x["age_minutes"] <= 360
        )
    ]

    high_recent = [
        x for x in recent
        if x["impact"] == "HIGH"
    ]

    bullish = sum(
        1 for x in recent
        if x["headline_bias"] == "BULLISH"
    )

    bearish = sum(
        1 for x in recent
        if x["headline_bias"] == "BEARISH"
    )

    if high_recent:
        risk = "HIGH"
    elif any(
        x["impact"] == "MEDIUM"
        for x in recent
    ):
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if bullish > bearish:
        bias = "BULLISH"
    elif bearish > bullish:
        bias = "BEARISH"
    else:
        bias = "NEUTRAL"

    top = (
        recent[0]
        if recent
        else None
    )

    return {
        "risk": risk,
        "headline_bias": bias,
        "top": top,
        "count": len(recent),
    }


def convert_index_to_ny(df):
    if df.empty:
        return df

    result = df.copy()

    try:
        if result.index.tz is None:
            result.index = result.index.tz_localize("UTC")

        result.index = result.index.tz_convert(NY_TZ)

    except Exception:
        pass

    return result


def regular_session_only(df):
    if df.empty:
        return df

    result = convert_index_to_ny(df)

    try:
        result = result.between_time(
            "09:30",
            "16:00",
            inclusive="left"
        )
    except Exception:
        pass

    return result


@st.cache_data(ttl=3600)
def get_nyse_schedule(day_string):
    day = pd.Timestamp(day_string).date()

    return NYSE.schedule(
        start_date=day,
        end_date=day,
    )


def normalize_timestamp_to_ny(timestamp):
    ts = pd.Timestamp(timestamp)

    if ts.tzinfo is None:
        ts = ts.tz_localize("UTC")

    return ts.tz_convert(NY_TZ)


def get_market_status(last_timestamp, ticker=None, now=None):
    now_ny = pd.Timestamp.now(tz=NY_TZ) if now is None else normalize_timestamp_to_ny(now)
    if now_ny.weekday() >= 5:
        return "WEEKEND", now_ny
    schedule = get_nyse_schedule(str(now_ny.date()))
    if schedule.empty:
        return "HOLIDAY", now_ny
    opening = schedule.iloc[0]["market_open"].tz_convert(NY_TZ)
    closing = schedule.iloc[0]["market_close"].tz_convert(NY_TZ)
    if opening <= now_ny < closing:
        state, start = "LIVE", opening
    elif ticker != "^GSPC" and now_ny.normalize() + pd.Timedelta(hours=4) <= now_ny < opening:
        state, start = "PRE-MARKET", now_ny.normalize() + pd.Timedelta(hours=4)
    elif ticker != "^GSPC" and closing <= now_ny < now_ny.normalize() + pd.Timedelta(hours=20):
        state, start = "POST-MARKET", closing
    else:
        return "CLOSED", now_ny
    try:
        stamp = normalize_timestamp_to_ny(last_timestamp)
        age = (now_ny - stamp).total_seconds() / 60
        # A previous-session quote never certifies a fresh pre/post/opening signal.
        fresh = stamp >= start and 0 <= age <= 3
        return (state if fresh else "STALE"), now_ny
    except (ValueError, TypeError):
        return "UNKNOWN", now_ny


# ============================================================
# RESAMPLING / INDICATORS
# ============================================================

def resample_ohlc(df, rule):
    """Vectorized exchange-local bins, separated at pre/open/post boundaries."""
    if df.empty:
        return pd.DataFrame()
    data = convert_index_to_ny(df).sort_index()
    data = data[~data.index.duplicated(keep="last")]
    schedule = hunter_schedule_range(str(data.index[0].date()), str(data.index[-1].date()))
    if schedule.empty:
        return data.iloc[:0]
    openings = {d.date(): r["market_open"].value for d,r in schedule.iterrows()}
    closings = {d.date(): r["market_close"].value for d,r in schedule.iterrows()}
    dates = data.index.date
    op = np.array([openings.get(d, 0) for d in dates], dtype="int64")
    cl = np.array([closings.get(d, 0) for d in dates], dtype="int64")
    stamp = data.index.as_unit("ns").asi8
    midnight = data.index.normalize().as_unit("ns").asi8
    pre = midnight + pd.Timedelta(hours=4).value
    post = midnight + pd.Timedelta(hours=20).value
    valid = (op > 0) & (stamp >= pre) & (stamp < post)
    anchor = np.where(stamp < op, pre, np.where(stamp < cl, op, cl))
    width = pd.Timedelta(rule).value
    labels = anchor + ((stamp-anchor)//width)*width
    data = data.loc[valid].copy()
    data.index = pd.to_datetime(labels[valid], utc=True).tz_convert(NY_TZ)
    return data.groupby(level=0).agg({"Open":"first","High":"max","Low":"min","Close":"last","Volume":"sum"}).dropna(subset=["Open","High","Low","Close"])


def ema(series, length):
    return series.ewm(
        span=length,
        adjust=False
    ).mean()


def rsi(series, length=14):
    delta = series.diff()

    gain = delta.clip(lower=0)
    loss = -delta.clip(upper=0)

    avg_gain = gain.ewm(
        alpha=1 / length,
        adjust=False
    ).mean()

    avg_loss = loss.ewm(
        alpha=1 / length,
        adjust=False
    ).mean()

    rs = avg_gain / avg_loss.replace(0, np.nan)

    output = 100 - (
        100 / (1 + rs)
    )

    output = output.mask((avg_loss == 0) & (avg_gain > 0), 100.)
    output = output.mask((avg_gain == 0) & (avg_loss > 0), 0.)
    return output.fillna(50)


def atr(df, length=14):
    if df.empty:
        return pd.Series(dtype=float)

    high_low = df["High"] - df["Low"]

    high_close = (
        df["High"] -
        df["Close"].shift()
    ).abs()

    low_close = (
        df["Low"] -
        df["Close"].shift()
    ).abs()

    true_range = pd.concat(
        [high_low, high_close, low_close],
        axis=1
    ).max(axis=1)

    return true_range.rolling(
        length,
        min_periods=5
    ).mean()


def calculate_vwap(df):
    if df.empty:
        return pd.Series(dtype=float)
    typical = (df["High"] + df["Low"] + df["Close"]) / 3
    volume = df["Volume"].fillna(0).clip(lower=0)
    # Missing index volume is unknown, not an invented volume-weighted price.
    if volume.sum() <= 0:
        return pd.Series(np.nan, index=df.index)
    intraday = len(df) > 1 and df.index.to_series().diff().dropna().median() < pd.Timedelta(days=1)
    if intraday:
        groups = pd.DatetimeIndex(df.index).date
        numerator = (typical*volume).groupby(groups).cumsum()
        denominator = volume.groupby(groups).cumsum()
    else:
        numerator = (typical*volume).rolling(20, min_periods=5).sum()
        denominator = volume.rolling(20, min_periods=5).sum()
    return numerator / denominator.replace(0, np.nan)


# ============================================================
# SIGNAL ENGINE
# ============================================================

def analyze_timeframe(df):
    default = {
        "signal": "WAIT",
        "score": 0,
        "rsi": 50.0, "available": False,
    }

    if df.empty or len(df) < 21:
        return default

    close = df["Close"]

    ema9 = ema(close, 9)
    ema21 = ema(close, 21)

    rsi_series = rsi(close, 14)
    vwap_series = calculate_vwap(df)

    price = float(close.iloc[-1])
    score = 0

    if ema9.iloc[-1] > ema21.iloc[-1]:
        score += 2
    elif ema9.iloc[-1] < ema21.iloc[-1]:
        score -= 2

    if price > ema9.iloc[-1]:
        score += 1
    elif price < ema9.iloc[-1]:
        score -= 1

    current_rsi = float(
        rsi_series.iloc[-1]
    )

    if current_rsi >= 55:
        score += 1
    elif current_rsi <= 45:
        score -= 1

    if (
        not vwap_series.empty
        and not pd.isna(vwap_series.iloc[-1])
    ):
        if price > vwap_series.iloc[-1]:
            score += 1
        elif price < vwap_series.iloc[-1]:
            score -= 1

    if len(close) >= 4:
        momentum = (
            float(close.iloc[-1]) -
            float(close.iloc[-4])
        )

        if momentum > 0:
            score += 1
        elif momentum < 0:
            score -= 1

    if score >= 3:
        signal = "CALL"
    elif score <= -3:
        signal = "PUT"
    else:
        signal = "WAIT"

    return {
        "signal": signal,
        "score": score,
        "rsi": current_rsi, "available": True,
    }


FRAME_WEIGHTS = dict(HUNTER_WEIGHTS)


def compute_master(results, weights=None):
    weights = FRAME_WEIGHTS if weights is None else weights
    active = {tf: w for tf,w in weights.items() if w > 0 and tf in results and results[tf].get("available", True)}
    if not active:
        return "WAIT", 0, 0.
    direction_score = sum(results[tf]["score"]*w for tf,w in active.items()) / (6*sum(active.values()))*100
    signal = "CALL" if direction_score >= 25 else "PUT" if direction_score <= -25 else "WAIT"
    return signal, min(100, round(abs(direction_score))), direction_score


def nearest_liquidity_levels(df, price, atr_value):
    """
    Price-structure liquidity proxy.
    Not Level 2 and not hidden dealer liquidity.
    """

    if df.empty:
        return price + atr_value, price - atr_value

    candidates_above = []
    candidates_below = []

    minimum_distance = max(
        atr_value * 0.05,
        price * 0.00002,
    )

    for window in [15, 30, 60, 120]:
        sample = df.tail(window)

        if sample.empty:
            continue

        hi = float(sample["High"].max())
        lo = float(sample["Low"].min())

        if hi > price + minimum_distance:
            candidates_above.append(hi)

        if lo < price - minimum_distance:
            candidates_below.append(lo)

    liquidity_above = (
        min(candidates_above)
        if candidates_above
        else price + atr_value
    )

    liquidity_below = (
        max(candidates_below)
        if candidates_below
        else price - atr_value
    )

    return liquidity_above, liquidity_below



# ============================================================
# CANDLE / LAUNCH ENGINE
# ============================================================

def candle_context_trend(df, bars=5):
    if df.empty or len(df) < bars + 1:
        return "FLAT"

    start = float(df["Close"].iloc[-bars-1])
    end = float(df["Close"].iloc[-2])

    move = end - start

    if move > 0:
        return "UP"

    if move < 0:
        return "DOWN"

    return "FLAT"


def detect_candle_pattern(df):
    """
    Context-aware candlestick classification.
    Candles are confirmation tools only; they do not trigger trades alone.
    """
    default = {
        "pattern": "NONE",
        "bias": "NEUTRAL",
        "score": 0,
        "body_ratio": 0.0,
    }

    if df.empty or len(df) < 3:
        return default

    c = df.iloc[-1]
    p = df.iloc[-2]

    o = float(c["Open"])
    h = float(c["High"])
    l = float(c["Low"])
    cl = float(c["Close"])

    po = float(p["Open"])
    pcl = float(p["Close"])

    rng = max(h - l, 1e-12)
    body = abs(cl - o)
    upper = h - max(o, cl)
    lower = min(o, cl) - l
    body_ratio = body / rng

    trend = candle_context_trend(df)

    current_bull = cl > o
    current_bear = cl < o
    prev_bull = pcl > po
    prev_bear = pcl < po

    # Doji = indecision, not directional by itself.
    if body_ratio <= 0.10:
        return {
            "pattern": "DOJI",
            "bias": "NEUTRAL",
            "score": 0,
            "body_ratio": body_ratio,
        }

    # Bullish engulfing
    if (
        prev_bear
        and current_bull
        and o <= pcl
        and cl >= po
    ):
        return {
            "pattern": "BULLISH ENGULFING",
            "bias": "CALL",
            "score": 2,
            "body_ratio": body_ratio,
        }

    # Bearish engulfing
    if (
        prev_bull
        and current_bear
        and o >= pcl
        and cl <= po
    ):
        return {
            "pattern": "BEARISH ENGULFING",
            "bias": "PUT",
            "score": -2,
            "body_ratio": body_ratio,
        }

    # Hammer after a decline
    if (
        trend == "DOWN"
        and lower >= max(body * 2.0, rng * 0.45)
        and upper <= max(body * 0.7, rng * 0.15)
    ):
        return {
            "pattern": "HAMMER",
            "bias": "CALL",
            "score": 1,
            "body_ratio": body_ratio,
        }

    # Inverted hammer after a decline
    if (
        trend == "DOWN"
        and upper >= max(body * 2.0, rng * 0.45)
        and lower <= max(body * 0.7, rng * 0.15)
    ):
        return {
            "pattern": "INVERTED HAMMER",
            "bias": "CALL",
            "score": 1,
            "body_ratio": body_ratio,
        }

    # Shooting star after a rise
    if (
        trend == "UP"
        and upper >= max(body * 2.0, rng * 0.45)
        and lower <= max(body * 0.7, rng * 0.15)
    ):
        return {
            "pattern": "SHOOTING STAR",
            "bias": "PUT",
            "score": -1,
            "body_ratio": body_ratio,
        }

    # Strong body / marubozu-style impulse
    if (
        body_ratio >= 0.80
        and upper <= rng * 0.12
        and lower <= rng * 0.12
    ):
        if current_bull:
            return {
                "pattern": "BULLISH IMPULSE",
                "bias": "CALL",
                "score": 1,
                "body_ratio": body_ratio,
            }

        if current_bear:
            return {
                "pattern": "BEARISH IMPULSE",
                "bias": "PUT",
                "score": -1,
                "body_ratio": body_ratio,
            }

    return default


def detect_structure(df, lookback=20):
    default = {
        "structure": "RANGE",
        "bias": "NEUTRAL",
        "score": 0,
        "level": np.nan,
    }

    if df.empty or len(df) < lookback + 2:
        return default

    current = df.iloc[-1]
    history = df.iloc[-lookback-1:-1]

    prior_high = float(history["High"].max())
    prior_low = float(history["Low"].min())

    close = float(current["Close"])
    high = float(current["High"])
    low = float(current["Low"])

    prior_trend = candle_context_trend(df, bars=6)

    # Require close beyond structure for a real BOS.
    if close > prior_high:
        label = (
            "BULLISH CHOCH"
            if prior_trend == "DOWN"
            else "BULLISH BOS"
        )

        return {
            "structure": label,
            "bias": "CALL",
            "score": 2,
            "level": prior_high,
        }

    if close < prior_low:
        label = (
            "BEARISH CHOCH"
            if prior_trend == "UP"
            else "BEARISH BOS"
        )

        return {
            "structure": label,
            "bias": "PUT",
            "score": -2,
            "level": prior_low,
        }

    # Wick sweep without close confirmation.
    if high > prior_high and close <= prior_high:
        return {
            "structure": "HIGH LIQUIDITY SWEEP",
            "bias": "PUT",
            "score": -1,
            "level": prior_high,
        }

    if low < prior_low and close >= prior_low:
        return {
            "structure": "LOW LIQUIDITY SWEEP",
            "bias": "CALL",
            "score": 1,
            "level": prior_low,
        }

    return default


def detect_volume_expansion(df, length=20):
    default = {
        "ratio": np.nan,
        "state": "N/A",
        "score": 0,
    }

    if (
        df.empty
        or "Volume" not in df.columns
        or len(df) < length + 2
    ):
        return default

    current_volume = float(df["Volume"].iloc[-1])
    history = df["Volume"].iloc[-length-1:-1].replace(0, np.nan)

    median_volume = float(history.median()) if not history.dropna().empty else 0.0

    if current_volume <= 0 or median_volume <= 0:
        return default

    ratio = current_volume / median_volume

    candle_direction = np.sign(
        float(df["Close"].iloc[-1]) -
        float(df["Open"].iloc[-1])
    )

    if ratio >= 1.50:
        return {
            "ratio": ratio,
            "state": "EXPANSION",
            "score": int(candle_direction),
        }

    return {
        "ratio": ratio,
        "state": "NORMAL",
        "score": 0,
    }


def detect_momentum_acceleration(df):
    default = {
        "state": "FLAT",
        "score": 0,
        "value": 0.0,
    }

    if df.empty or len(df) < 10:
        return default

    close = df["Close"]

    current_leg = (
        float(close.iloc[-1]) -
        float(close.iloc[-4])
    )

    previous_leg = (
        float(close.iloc[-4]) -
        float(close.iloc[-7])
    )

    acceleration = current_leg - previous_leg

    atr_values = atr(df, 14).replace(0, np.nan).dropna()

    if atr_values.empty:
        threshold = max(
            abs(float(close.iloc[-1])) * 0.0002,
            1e-6,
        )
    else:
        threshold = max(
            float(atr_values.iloc[-1]) * 0.25,
            1e-6,
        )

    if acceleration > threshold:
        return {
            "state": "ACCELERATING UP",
            "score": 1,
            "value": acceleration,
        }

    if acceleration < -threshold:
        return {
            "state": "ACCELERATING DOWN",
            "score": -1,
            "value": acceleration,
        }

    return {
        "state": "STABLE",
        "score": 0,
        "value": acceleration,
    }


def analyze_launch_frame(df):
    candle = detect_candle_pattern(df)
    structure = detect_structure(df)
    volume = detect_volume_expansion(df)
    momentum = detect_momentum_acceleration(df)

    score = (
        candle["score"]
        + structure["score"]
        + volume["score"]
        + momentum["score"]
    )

    return {
        "candle": candle,
        "structure": structure,
        "volume": volume,
        "momentum": momentum,
        "score": score,
    }


LAUNCH_FRAME_WEIGHTS = {
    "1m": 1.00,
    "3m": 1.25,
    "5m": 1.50,
    "15m": 1.25,
}


def compute_launch_engine(timeframes):
    details = {}

    weighted = 0.0
    max_abs = 0.0

    # Max per frame: candle 2 + structure 2 + volume 1 + momentum 1 = 6
    for tf, weight in LAUNCH_FRAME_WEIGHTS.items():
        analysis = analyze_launch_frame(
            timeframes[tf]
        )

        details[tf] = analysis

        weighted += (
            analysis["score"] * weight
        )

        max_abs += 6 * weight

    normalized = (
        weighted / max_abs * 100
        if max_abs > 0
        else 0.0
    )

    strength = min(
        int(round(abs(normalized))),
        100,
    )

    if normalized >= 18:
        signal = "CALL"
    elif normalized <= -18:
        signal = "PUT"
    else:
        signal = "WAIT"

    return {
        "signal": signal,
        "strength": strength,
        "score": normalized,
        "details": details,
    }


def launch_summary_text(launch_engine):
    signal = launch_engine["signal"]
    strength = launch_engine["strength"]

    if signal == "CALL":
        return f"CALL LAUNCH {strength}%"

    if signal == "PUT":
        return f"PUT LAUNCH {strength}%"

    return f"WAIT {strength}%"

# ============================================================
# WAVE ENGINE
# ============================================================

def build_previous_results(timeframes):
    previous = {}

    for tf, df in timeframes.items():
        if df is None or df.empty or len(df) < 13:
            previous[tf] = {
                "signal": "WAIT",
                "score": 0,
                "rsi": 50.0, "available": False,
            }
        else:
            previous[tf] = analyze_timeframe(
                df.iloc[:-1]
            )

    return previous


def count_signal(results, frames, signal):
    return sum(
        1
        for tf in frames
        if results.get(tf, {}).get("signal") == signal
    )


def determine_wave_stage(
    results,
    previous_results,
    master_signal,
    previous_master,
    signal_strength,
    current_price,
    zero_low,
    zero_high,
):
    short_frames = ["1m", "3m", "5m", "10m"]
    confirm_frames = ["3m", "5m", "15m"]

    current_call_confirm = count_signal(
        results,
        confirm_frames,
        "CALL"
    )

    current_put_confirm = count_signal(
        results,
        confirm_frames,
        "PUT"
    )

    previous_call_confirm = count_signal(
        previous_results,
        confirm_frames,
        "CALL"
    )

    previous_put_confirm = count_signal(
        previous_results,
        confirm_frames,
        "PUT"
    )

    short_call = count_signal(
        results,
        short_frames,
        "CALL"
    )

    short_put = count_signal(
        results,
        short_frames,
        "PUT"
    )

    in_zero = (
        zero_low <= current_price <= zero_high
    )

    # Confirmed directional flip
    if (
        master_signal == "CALL"
        and current_call_confirm >= 2
        and previous_put_confirm >= 2
    ):
        return "CONFIRMED CALL"

    if (
        master_signal == "PUT"
        and current_put_confirm >= 2
        and previous_call_confirm >= 2
    ):
        return "CONFIRMED PUT"

    # New wave start
    if (
        master_signal == "CALL"
        and previous_master == "WAIT"
        and current_call_confirm >= 2
    ):
        return "START CALL"

    if (
        master_signal == "PUT"
        and previous_master == "WAIT"
        and current_put_confirm >= 2
    ):
        return "START PUT"

    # Zero/reversal watch
    if in_zero:
        return "ZERO WATCH"

    # Weakening logic
    if master_signal == "CALL":
        if (
            short_put >= 2
            or results["1m"]["signal"] == "PUT"
            or results["3m"]["signal"] == "PUT"
        ):
            return "CALL WEAKENING"

        if (
            current_call_confirm >= 2
            and signal_strength >= 55
        ):
            return "CALL ACTIVE"

        return "CALL WATCH"

    if master_signal == "PUT":
        if (
            short_call >= 2
            or results["1m"]["signal"] == "CALL"
            or results["3m"]["signal"] == "CALL"
        ):
            return "PUT WEAKENING"

        if (
            current_put_confirm >= 2
            and signal_strength >= 55
        ):
            return "PUT ACTIVE"

        return "PUT WATCH"

    # Master WAIT but short frames lean one side
    if short_call >= 3:
        return "CALL WATCH"

    if short_put >= 3:
        return "PUT WATCH"

    return "WAIT"


def determine_action(
    market_status,
    wave_stage,
    master_signal,
    signal_strength,
    results,
    current_price,
    entry_low,
    entry_high,
    target1,
    current_atr,
):
    live = market_status in HUNTER_ACTIVE_STATES

    call_confirm = count_signal(
        results,
        ["3m", "5m", "15m"],
        "CALL"
    )

    put_confirm = count_signal(
        results,
        ["3m", "5m", "15m"],
        "PUT"
    )

    if entry_low <= current_price <= entry_high:
        entry_distance = 0.0
    elif current_price < entry_low:
        entry_distance = entry_low - current_price
    else:
        entry_distance = current_price - entry_high

    near_entry = entry_distance <= current_atr * 0.25

    # If price already reached/passed T1, do not chase a fresh entry.
    if target1 is not None:
        if master_signal == "CALL" and current_price >= target1:
            return "DO NOT CHASE — CALL WAVE EXTENDED"

        if master_signal == "PUT" and current_price <= target1:
            return "DO NOT CHASE — PUT WAVE EXTENDED"

    if wave_stage == "CONFIRMED CALL":
        if live and near_entry:
            return "PAPER CALL ENTRY"
        return (
            "CONFIRMED CALL — WAIT FOR ENTRY"
            if live
            else "LAST SESSION: CONFIRMED CALL"
        )

    if wave_stage == "CONFIRMED PUT":
        if live and near_entry:
            return "PAPER PUT ENTRY"
        return (
            "CONFIRMED PUT — WAIT FOR ENTRY"
            if live
            else "LAST SESSION: CONFIRMED PUT"
        )

    if wave_stage == "START CALL":
        return (
            "PAPER CALL WATCH"
            if live
            else "LAST SESSION: START CALL"
        )

    if wave_stage == "START PUT":
        return (
            "PAPER PUT WATCH"
            if live
            else "LAST SESSION: START PUT"
        )

    if wave_stage == "CALL ACTIVE":
        if (
            live
            and signal_strength >= 55
            and call_confirm == 3
            and near_entry
        ):
            return "STRONG PAPER CALL"

        if live and not near_entry:
            return "CALL ACTIVE — WAIT FOR PULLBACK"

        return "CALL WATCH"

    if wave_stage == "PUT ACTIVE":
        if (
            live
            and signal_strength >= 55
            and put_confirm == 3
            and near_entry
        ):
            return "STRONG PAPER PUT"

        if live and not near_entry:
            return "PUT ACTIVE — WAIT FOR PULLBACK"

        return "PUT WATCH"

    if "WEAKENING" in wave_stage:
        return "PROTECT PAPER PROFIT / NO NEW ENTRY"

    if wave_stage == "ZERO WATCH":
        return "WAIT FOR REVERSAL CONFIRMATION"

    if wave_stage == "CALL WATCH":
        return "CALL WATCH — WAIT FOR CONFIRMATION"

    if wave_stage == "PUT WATCH":
        return "PUT WATCH — WAIT FOR CONFIRMATION"

    return "WAIT — NO PAPER TRADE"


def distance_to_zone(price, low, high):
    if low <= price <= high:
        return 0.0

    if price < low:
        return low - price

    return price - high


def directional_distance(price, level, direction):
    if level is None:
        return None

    if direction == "CALL":
        return max(0.0, level - price)

    if direction == "PUT":
        return max(0.0, price - level)

    return abs(level - price)


def get_session_signal_age(symbol, master_signal, market_status, now_ny):
    """
    Tracks how long the current master CALL/PUT/WAIT has remained unchanged
    during the active Streamlit session.
    """
    key = f"signal_age_state_{symbol}"

    state = st.session_state.get(key)

    if (
        state is None
        or state.get("signal") != master_signal
    ):
        st.session_state[key] = {
            "signal": master_signal,
            "started_at": now_ny,
        }

    started_at = st.session_state[key]["started_at"]

    if market_status not in HUNTER_ACTIVE_STATES:
        return 0.0

    return max(
        0.0,
        (now_ny - started_at).total_seconds() / 60.0
    )


def init_paper_log():
    if "paper_trade_log" not in st.session_state:
        st.session_state.paper_trade_log = []

    if "paper_open_trades" not in st.session_state:
        st.session_state.paper_open_trades = {}


def maybe_open_paper_trade(
    symbol,
    action_text,
    now_ny,
    current_price,
    target1,
    target2,
    target3,
    invalidation,
):
    init_paper_log()

    entry_actions = {
        "STRONG PAPER CALL": "CALL",
        "PAPER CALL ENTRY": "CALL",
        "STRONG PAPER PUT": "PUT",
        "PAPER PUT ENTRY": "PUT",
    }

    direction = entry_actions.get(action_text)

    if direction is None:
        return

    if symbol in st.session_state.paper_open_trades:
        return

    trade = {
        "Symbol": symbol,
        "Direction": direction,
        "Entry Time": now_ny.strftime("%Y-%m-%d %H:%M:%S ET"),
        "Entry Price": float(current_price),
        "T1": None if target1 is None else float(target1),
        "T2": None if target2 is None else float(target2),
        "T3": None if target3 is None else float(target3),
        "Invalidation": None if invalidation is None else float(invalidation),
        "Best Price": float(current_price),
        "Status": "OPEN",
        "Exit Time": "",
        "Exit Price": None,
        "Result": "",
    }

    st.session_state.paper_open_trades[symbol] = trade
    st.session_state.paper_trade_log.append(trade)


def update_paper_trade(symbol, now_ny, current_price):
    init_paper_log()

    trade = st.session_state.paper_open_trades.get(symbol)

    if trade is None:
        return

    direction = trade["Direction"]

    if direction == "CALL":
        trade["Best Price"] = max(
            trade["Best Price"],
            float(current_price)
        )

        if (
            trade["Invalidation"] is not None
            and current_price <= trade["Invalidation"]
        ):
            trade["Status"] = "CLOSED"
            trade["Exit Time"] = now_ny.strftime("%Y-%m-%d %H:%M:%S ET")
            trade["Exit Price"] = float(current_price)
            trade["Result"] = "INVALIDATED"
            st.session_state.paper_open_trades.pop(symbol, None)

        elif (
            trade["T3"] is not None
            and current_price >= trade["T3"]
        ):
            trade["Status"] = "CLOSED"
            trade["Exit Time"] = now_ny.strftime("%Y-%m-%d %H:%M:%S ET")
            trade["Exit Price"] = float(current_price)
            trade["Result"] = "T3 HIT"
            st.session_state.paper_open_trades.pop(symbol, None)

        elif (
            trade["T2"] is not None
            and current_price >= trade["T2"]
        ):
            trade["Result"] = "T2 HIT"

        elif (
            trade["T1"] is not None
            and current_price >= trade["T1"]
        ):
            trade["Result"] = "T1 HIT"

    elif direction == "PUT":
        trade["Best Price"] = min(
            trade["Best Price"],
            float(current_price)
        )

        if (
            trade["Invalidation"] is not None
            and current_price >= trade["Invalidation"]
        ):
            trade["Status"] = "CLOSED"
            trade["Exit Time"] = now_ny.strftime("%Y-%m-%d %H:%M:%S ET")
            trade["Exit Price"] = float(current_price)
            trade["Result"] = "INVALIDATED"
            st.session_state.paper_open_trades.pop(symbol, None)

        elif (
            trade["T3"] is not None
            and current_price <= trade["T3"]
        ):
            trade["Status"] = "CLOSED"
            trade["Exit Time"] = now_ny.strftime("%Y-%m-%d %H:%M:%S ET")
            trade["Exit Price"] = float(current_price)
            trade["Result"] = "T3 HIT"
            st.session_state.paper_open_trades.pop(symbol, None)

        elif (
            trade["T2"] is not None
            and current_price <= trade["T2"]
        ):
            trade["Result"] = "T2 HIT"

        elif (
            trade["T1"] is not None
            and current_price <= trade["T1"]
        ):
            trade["Result"] = "T1 HIT"



HUNTER_STAR_COLORS = {"CALL": "#16a34a", "PUT": "#ef4444", "WAIT": "#f59e0b", "UNKNOWN": "#94a3b8"}


@st.cache_data(ttl=15, show_spinner=False)
def hunter_timeframes(minute_data, hour_data, daily_data, weekly_data):
    # hour_data carries the deeper native 5-minute history in this release.
    base5 = convert_index_to_ny(hour_data)
    fresh5 = resample_ohlc(minute_data, "5min")
    if not fresh5.empty:
        # The first downloaded day may start partway through a bucket; keep history for it.
        cutoff = fresh5.index[0] + pd.Timedelta(days=1)
        recent = fresh5.loc[fresh5.index >= cutoff]
        if not recent.empty:
            base5 = pd.concat([base5.loc[base5.index < recent.index[0]], recent]).sort_index()
    frames = {"1m": minute_data, "3m": resample_ohlc(minute_data, "3min"), "5m": base5, "Daily": daily_data}
    for tf, minutes in [("10m",10),("15m",15),("30m",30),("45m",45),("1H",60),("2H",120),("4H",240),("6H",360),("8H",480)]:
        frames[tf] = resample_ohlc(base5, f"{minutes}min")
    agg = {"Open":"first","High":"max","Low":"min","Close":"last","Volume":"sum"}
    for tf, rule in [("Weekly","W-MON"),("Monthly","MS")]:
        frames[tf] = daily_data.resample(rule, closed="left", label="left").agg(agg).dropna(subset=["Close"]) if not daily_data.empty else pd.DataFrame()
    return frames


@st.cache_data(ttl=15, show_spinner=False)
def hunter_minute_batch(tickers):
    return hunter_fetch_batch(tickers, "5d", "1m")

@st.cache_data(ttl=60, show_spinner=False)
def hunter_history_batch(tickers):
    return hunter_fetch_batch(tickers, "1mo", "5m")

@st.cache_data(ttl=900, show_spinner=False)
def hunter_daily_batch(tickers):
    return hunter_fetch_batch(tickers, "10y", "1d")

@st.cache_resource
def hunter_feed_memory():
    # Public market snapshots only; credentials and user settings never enter this cache.
    return {"lock": threading.RLock(), "last": {}, "retry_after": {}}


def hunter_fetch_batch(tickers, period, interval):
    memory = hunter_feed_memory()
    key = (tuple(tickers), period, interval)
    with memory["lock"]:
        if time.time() < memory["retry_after"].get(key, 0):
            return {ticker: hunter_stale_copy(memory["last"].get((key,ticker), pd.DataFrame())) for ticker in tickers}
        result = hunter_fetch_batch_uncached(tickers, period, interval)
        any_missing = False
        for ticker, frame in result.items():
            if frame.empty:
                any_missing = True
                result[ticker] = hunter_stale_copy(memory["last"].get((key,ticker), frame))
            else:
                memory["last"][(key,ticker)] = frame.copy()
        if any_missing:
            memory["retry_after"][key] = time.time()+60
        return result


def hunter_stale_copy(frame):
    result = frame.copy()
    result.attrs["feed_unavailable"] = True
    return result


def hunter_fetch_batch_uncached(tickers, period, interval):
    try:
        batch = yf.download(list(tickers), period=period, interval=interval,
                            group_by="ticker", auto_adjust=True, progress=False,
                            prepost=True, threads=False, timeout=12, ignore_tz=False)
    except Exception:
        batch = pd.DataFrame()
    result = {}
    for ticker in tickers:
        frame = pd.DataFrame()
        try:
            if batch is not None and not batch.empty:
                if isinstance(batch.columns, pd.MultiIndex):
                    frame = batch[ticker].copy() if ticker in batch.columns.get_level_values(0) else batch.xs(ticker,axis=1,level=1).copy()
                elif len(tickers) == 1:
                    frame = batch.copy()
                if {"Open","High","Low","Close"}.issubset(frame.columns):
                    for col in ["Open","High","Low","Close","Volume"]:
                        frame[col] = pd.to_numeric(frame[col], errors="coerce") if col in frame else 0.
                    frame = frame.replace([np.inf,-np.inf],np.nan).dropna(subset=["Open","High","Low","Close"])
                    frame = frame[(frame[["Open","High","Low","Close"]] > 0).all(axis=1)]
                    frame = frame[(frame["High"] >= frame[["Open","Close","Low"]].max(axis=1)) & (frame["Low"] <= frame[["Open","Close","High"]].min(axis=1))]
                    frame["Volume"] = frame["Volume"].fillna(0).clip(lower=0)
                    frame = frame.sort_index()
                    frame = frame[~frame.index.duplicated(keep="last")]
                    if interval != "1d":
                        frame = convert_index_to_ny(frame)
                        frame = frame.between_time("04:00", "20:00", inclusive="left")
                        if ticker == "^GSPC":
                            frame = regular_session_only(frame)
                else:
                    frame = pd.DataFrame()
        except (KeyError, TypeError, ValueError):
            frame = pd.DataFrame()
        result[ticker] = frame
    return result


def hunter_download_universe(tickers):
    minute = hunter_minute_batch(tickers)
    history = hunter_history_batch(tickers)
    daily = hunter_daily_batch(tickers)
    return {ticker: {"minute":minute[ticker],"hour":history[ticker],"daily":daily[ticker],"weekly":pd.DataFrame()} for ticker in tickers}


def hunter_star_snapshot(data, weights):
    frames = hunter_timeframes(data["minute"], data["hour"], data["daily"], data["weekly"])
    now = pd.Timestamp.now(tz=NY_TZ)
    frames = {tf: hunter_completed_frame(frame, tf, now) for tf,frame in frames.items()}
    last_ts = data["minute"].index[-1] if not data["minute"].empty else None
    results = {tf: analyze_timeframe(frame) for tf,frame in frames.items()}
    if last_ts is None or not any(r["available"] and weights.get(tf,0)>0 for tf,r in results.items()):
        return {"signal":"UNKNOWN","strength":None,"last_ts":last_ts}
    signal,strength,_ = compute_master(results, weights)
    return {"signal":signal,"strength":strength,"last_ts":last_ts}


def hunter_render_watchlist(universe, weights):
    hunter_require_user()
    if st.session_state.get("hunter_symbol") not in SYMBOLS:
        st.session_state["hunter_symbol"] = next(iter(SYMBOLS))
    st.markdown("**الأصل المختار — اضغط السهم لفتح تفاصيله**" if AR else "**Select an instrument to inspect its details**")
    labels = {"CALL": "كول" if AR else "CALL", "PUT": "بوت" if AR else "PUT",
              "WAIT": "محايد / انتظار" if AR else "Neutral / WAIT",
              "UNKNOWN": "بيانات غير كافية" if AR else "Insufficient data"}
    snapshots = {}
    for column, (symbol, ticker) in zip(st.columns(len(SYMBOLS)), SYMBOLS.items()):
        snapshot = hunter_star_snapshot(universe[ticker], weights)
        snapshots[symbol] = snapshot
        color = HUNTER_STAR_COLORS[snapshot["signal"]]
        selected = st.session_state["hunter_symbol"] == symbol
        with column:
            # Actual colored star glyph, not an uncolored star beside a colored circle.
            st.markdown(f"""<style>
              .st-key-hunter_pick_{symbol} button {{color:{color} !important;
                border: {'3' if selected else '1'}px solid {color} !important;
                min-height: 58px; width:100%;}}
              .st-key-hunter_pick_{symbol} button p {{color:{color} !important; font-weight:750;}}
            </style>""", unsafe_allow_html=True)
            if st.button(f"★ {symbol} · {labels[snapshot['signal']]}",
                         key=f"hunter_pick_{symbol}", width="stretch",
                         help=MARKET_NAMES[symbol]):
                st.session_state["hunter_symbol"] = symbol
                st.rerun()
            if snapshot["last_ts"] is not None:
                market_state, _ = get_market_status(snapshot["last_ts"], ticker)
                stamp = normalize_timestamp_to_ny(snapshot["last_ts"]).strftime("%m-%d %H:%M ET")
                st.caption(f"{display_status(market_state)} · {stamp}")
    st.caption(
        "أخضر: كول · أحمر: بوت · برتقالي: محايد/انتظار · رمادي: بيانات غير كافية. اللون يلخص اتجاه المحرك، وليس تأكيد دخول؛ عند إغلاق السوق يعكس آخر جلسة."
        if AR else
        "Green: CALL · Red: PUT · Orange: neutral/WAIT · Gray: insufficient data. Direction summary, not entry confirmation; when closed it reflects the last session."
    )
    return st.session_state["hunter_symbol"], snapshots


HUNTER_ANALYSIS_TFS = list(HUNTER_TFS)
HUNTER_FRAME_MINUTES = {"1m":1,"3m":3,"5m":5,"10m":10,"15m":15,"30m":30,"45m":45,
                        "1H":60,"2H":120,"4H":240,"6H":360,"8H":480}


def hunter_select_analysis_timeframe(default):
    # Navigation preference for this session, never a write to owner settings.
    hunter_require_user()
    default = "1H" if default == "60m" else default
    if st.session_state.get("hunter_analysis_tf") not in HUNTER_ANALYSIS_TFS:
        st.session_state["hunter_analysis_tf"] = default if default in HUNTER_ANALYSIS_TFS else "5m"
    labels = {"1m": "دقيقة", "3m": "3 دقائق", "5m": "5 دقائق", "15m": "ربع ساعة",
              "10m":"10 دقائق", "30m":"نصف ساعة", "45m":"45 دقيقة", "1H":"ساعة", "2H":"ساعتان", "4H":"4 ساعات", "6H":"6 ساعات", "8H":"8 ساعات", "Daily":"يومي", "Weekly":"أسبوعي", "Monthly":"شهري"}
    selected = st.radio("فريم التحليل والأهداف" if AR else "Analysis & target timeframe",
                        HUNTER_ANALYSIS_TFS, horizontal=True,
                        format_func=lambda tf: labels[tf] if AR else tf,
                        key="hunter_analysis_tf")
    st.caption(
        "اختيارك هنا يغيّر الرسم والأهداف ومستويات السعر وقراءة الشموع لهذه الجلسة. اتجاه النجوم يبقى ملخص الفريمات كلها."
        if AR else "This selection updates the chart, targets, price levels and candle focus for this session. Stars remain the multi-timeframe direction summary."
    )
    return selected


@st.cache_data(ttl=3600, show_spinner=False)
def hunter_schedule_range(start, end):
    return NYSE.schedule(start_date=start, end_date=end)


@st.cache_data(ttl=60, show_spinner=False)
def hunter_bar_ends(frame, tf):
    if frame.empty:
        return pd.DatetimeIndex([], tz="UTC")
    stamps = pd.DatetimeIndex(frame.index)
    schedule = hunter_schedule_range(str(stamps[0].date()), str(stamps[-1].date()+pd.Timedelta(days=35)))
    closes = {day.date():row["market_close"] for day,row in schedule.iterrows()}
    opens = {day.date():row["market_open"] for day,row in schedule.iterrows()}
    ends = []
    for stamp in stamps:
        day = stamp.date()
        if tf in ("Daily","Weekly","Monthly"):
            if tf == "Daily":
                end = closes.get(day,pd.NaT)
            else:
                start = day-pd.Timedelta(days=day.weekday()) if tf == "Weekly" else day.replace(day=1)
                stop = start+pd.Timedelta(days=7) if tf == "Weekly" else (pd.Timestamp(start)+pd.offsets.MonthBegin(1)).date()
                matches = [close for date,close in closes.items() if start <= date < stop]
                end = max(matches) if matches else pd.NaT
        else:
            start = normalize_timestamp_to_ny(stamp)
            opening,closing = opens.get(start.date()), closes.get(start.date())
            if closing is None:
                end = pd.NaT
            else:
                pre,post = start.normalize()+pd.Timedelta(hours=4), start.normalize()+pd.Timedelta(hours=20)
                if not pre <= start < post:
                    end = pd.NaT
                else:
                    boundary = opening if start < opening else closing if start < closing else post
                    end = min(start+pd.Timedelta(minutes=HUNTER_FRAME_MINUTES[tf]),boundary)
        ends.append(end)
    return pd.DatetimeIndex(pd.to_datetime(ends,utc=True))


def hunter_completed_frame(frame, tf, as_of):
    if frame.empty:
        return frame.copy()
    ends = hunter_bar_ends(frame, tf)
    now = pd.Timestamp(as_of)
    now = now.tz_localize("UTC") if now.tzinfo is None else now.tz_convert("UTC")
    return frame.loc[ends.notna() & (ends <= now)].copy()


def hunter_target_levels(frame, direction, price):
    """Rolling scenario from the timestamped last price; closed-bar ATR/pivots. Not a fixed trade."""
    if len(frame) < 21:
        return None
    volatility = float(atr(frame, 14).iloc[-1])
    if not np.isfinite(volatility) or volatility <= 0:
        return None
    anchor = float(price)
    if not np.isfinite(anchor):
        return None
    liquidity_above, liquidity_below = nearest_liquidity_levels(frame, price, volatility)
    sign = 1 if direction == "CALL" else -1 if direction == "PUT" else 0
    zero_center = liquidity_above if sign == 1 else liquidity_below if sign == -1 else price
    result = {
        "atr": volatility, "anchor": anchor,
        "entry_low": anchor - .15 * volatility, "entry_high": anchor + .15 * volatility,
        "liquidity_above": liquidity_above, "liquidity_below": liquidity_below,
        "zero_low": zero_center - .30 * volatility, "zero_high": zero_center + .30 * volatility,
        "targets": [None, None, None], "sources": [], "invalidation": None,
    }
    if not sign:
        return result
    recent = frame.tail(80)
    column = "High" if sign == 1 else "Low"
    values = recent[column].to_numpy(dtype=float)
    pivots = []
    # A pivot is used only after two bars have already closed to its right.
    for i in range(2, len(values) - 2):
        neighbors = np.r_[values[i-2:i], values[i+1:i+3]]
        if (sign == 1 and np.all(values[i] > neighbors)) or (sign == -1 and np.all(values[i] < neighbors)):
            distance = sign * (values[i] - anchor)
            if distance > 0:
                pivots.append(distance)
    pivots.sort()
    targets, sources, previous = [], [], 0.0
    for multiplier in [1., 2., 3.]:
        minimum = max(multiplier * volatility, previous + volatility)
        # Prefer an observed pivot within the next ATR band, otherwise use the ATR reference.
        candidates = [distance for distance in pivots if minimum <= distance <= minimum + volatility]
        distance = candidates[0] if candidates else minimum
        targets.append(anchor + sign * distance)
        sources.append("pivot" if candidates else "atr")
        previous = distance
    result["targets"], result["sources"] = targets, sources
    result["invalidation"] = anchor - sign * 1.15 * volatility
    return result


def hunter_timing_estimate(frame, tf, direction, price, targets, market_state,
                           invalidation=None, local_signal=None):
    """Uncalibrated kinematic scenario, NOT a probability or a promised hit time.

    Signed progress and efficiency penalize backtracking. Quartiles describe
    recent positive speeds, not forecast confidence intervals. Volume is
    reported as context only, not assigned an invented causal speed multiplier.
    """
    def unavailable(reason):
        return {"reason": reason, "estimates": [], "volume_ratio": None}
    if market_state not in HUNTER_ACTIVE_STATES:
        return unavailable("market")
    if direction not in ("CALL", "PUT"):
        return unavailable("neutral")
    if local_signal is not None and local_signal != direction:
        return unavailable("conflict")
    sign = 1 if direction == "CALL" else -1
    if invalidation is not None and sign * (price - invalidation) <= 0:
        return unavailable("invalidated")
    if len(frame) < 21:
        return unavailable("history")
    sample = frame.tail(61)
    steps = sign * sample["Close"].diff().to_numpy(dtype=float)[1:]
    if tf in ("Daily", "Weekly", "Monthly"):
        periods = np.full(len(steps), 1. if tf == "Daily" else 5. if tf == "Weekly" else 21.)
        unit = "sessions"
        valid = np.isfinite(steps)
    else:
        ends = hunter_bar_ends(sample, tf)
        periods = np.diff(ends.asi8) / (60 * 1e9)
        dates = ends.tz_convert(NY_TZ).date
        same_session = dates[1:] == dates[:-1]
        valid = same_session & np.isfinite(steps) & (periods > 0)
        unit = "minutes"
    steps, periods = steps[valid], periods[valid]
    if len(steps) < 12:
        return unavailable("history")
    absolute = float(np.abs(steps).sum())
    efficiency = float(steps.sum() / absolute) if absolute else 0.
    if efficiency < .20 or np.mean(steps > 0) < .55 or steps[-3:].sum() <= 0:
        return unavailable("momentum")
    speeds = steps[steps > 0] / periods[steps > 0]
    slow, fast = np.quantile(speeds, [.25, .75]) * efficiency
    if not np.isfinite(slow) or slow <= 0 or not np.isfinite(fast) or fast <= 0:
        return unavailable("momentum")
    estimates = []
    for target in targets:
        if target is None or not np.isfinite(target):
            estimates.append({"status": "unavailable"})
            continue
        distance = sign * (target - price)
        if distance <= 0:
            estimates.append({"status": "passed"})
            continue
        lower, upper = distance / fast, distance / slow
        # Extrapolations exceeding 30 bars are not shown as precise durations.
        horizon = 30 * (1 if tf == "Daily" else 5 if tf == "Weekly" else 21 if tf == "Monthly" else HUNTER_FRAME_MINUTES[tf])
        if upper > horizon:
            estimates.append({"status": "horizon"})
        else:
            estimates.append({"status": "range", "low": max(1, math.floor(lower)),
                              "high": max(1, math.ceil(upper)), "unit": unit})
    volume = sample.get("Volume", pd.Series(dtype=float)).tail(21)
    baseline = float(volume.iloc[:-1].median()) if len(volume) >= 2 else 0.
    ratio = float(volume.iloc[-1] / baseline) if baseline > 0 and volume.iloc[-1] > 0 else None
    return {"reason": None, "estimates": estimates, "efficiency": efficiency,
            "volume_ratio": ratio, "slow": float(slow), "fast": float(fast)}


def hunter_render_timing(timing, tf):
    st.markdown("##### الزمن الحركي التقريبي — " + tf if AR else "##### Conditional travel-time scenario — " + tf)
    reasons = {
        "market": ("لا تقدير زمني حاليًا: السوق مغلق أو البيانات متأخرة. المستويات المعروضة تخص آخر بيانات متاحة.", "No timing estimate: market closed or data stale."),
        "neutral": ("لا تقدير زمني: الاتجاه محايد.", "No timing estimate: neutral direction."),
        "conflict": ("لا تقدير زمني: اتجاه الفريم المختار لا يؤكد الاتجاه العام.", "No timing estimate: selected timeframe conflicts with, or does not confirm, the overall direction."),
        "invalidated": ("لا تقدير زمني: السعر تجاوز مستوى إلغاء هذا السيناريو.", "No timing estimate: this scenario is invalidated."),
        "history": ("لا توجد شموع مكتملة كافية لتقدير زمني.", "Insufficient completed bars for timing."),
        "momentum": ("لا تقدير زمني بالحساب الحالي: الزخم ضعيف أو الحركة متذبذبة.", "No timing range: weak or unstable directional progress."),
    }
    if timing["reason"]:
        st.info(reasons[timing["reason"]][0 if AR else 1])
        return
    for column, number, estimate in zip(st.columns(3), [1, 2, 3], timing["estimates"]):
        with column:
            if estimate["status"] == "range":
                unit = ("دقيقة تداول" if AR else "trading min") if estimate["unit"] == "minutes" else ("جلسة تداول" if AR else "trading sessions")
                text = f"{estimate['low']}–{estimate['high']} {unit}"
            elif estimate["status"] == "passed":
                text = "السعر تجاوز المستوى" if AR else "Price beyond level"
            elif estimate["status"] == "horizon":
                text = "خارج نطاق التقدير" if AR else "Beyond estimate horizon"
            else:
                text = "غير متاح" if AR else "Unavailable"
            st.metric(f"T{number}", text)
    st.caption(
        "هذا نطاق حركي افتراضي من آخر سعر شمعة متاحة إذا استمر نمط الحركة؛ ليس موعد وصول أو احتمال نجاح أو نطاق ثقة إحصائيًا. لا يشمل فترات إغلاق السوق أو أثر التضخم والأخبار المستقبلية."
        if AR else "Uncalibrated travel-time scenario from the latest available bar price if recent movement persists. Not a promised hit time, success probability or statistical confidence interval. Excludes market closures and future macro/news effects."
    )
    ratio = timing["volume_ratio"]
    st.caption((f"الحجم النسبي: {ratio:.2f}× — للقراءة فقط" if AR else f"Relative volume: {ratio:.2f}× — context only")
               if ratio is not None else ("الحجم غير متاح لهذا الأصل؛ لا يدخل في تقدير الزمن." if AR else "Volume unavailable for this instrument; not used in the time estimate."))


# ============================================================
# LANGUAGE / LOCALIZATION
# ============================================================

hunter_account_bar()
hunter_editing = hunter_admin_panel(hunter_settings)
# Reload saved values, including changes made by another owner session.
hunter_settings = hunter_load_settings()
FRAME_WEIGHTS = dict(hunter_settings["frame_weights"])
LAUNCH_FRAME_WEIGHTS = dict(hunter_settings["launch_weights"])
PRICE_BOARD_REFRESH_SECONDS = hunter_settings["refresh_seconds"]
if not hunter_editing:
    st_autorefresh(interval=PRICE_BOARD_REFRESH_SECONDS * 1000, key="hunter_refresh")
language = hunter_settings["language"]

AR = language == "العربية"

TEXT = {
    "subtitle": {
        "en": "Market Research & Paper Trading Console",
        "ar": "واجهة بحث السوق والتداول الورقي",
    },
    "paper_only": {
        "en": "PAPER ONLY",
        "ar": "تداول ورقي فقط",
    },
    "wave_engine": {
        "en": "RESEARCH MODE",
        "ar": "وضع البحث",
    },
    "auto_refresh": {
        "en": "AUTO UPDATE",
        "ar": "تحديث تلقائي",
    },
    "selected_market": {
        "en": "SELECTED INSTRUMENT",
        "ar": "الأصل المختار",
    },
    "price_board": {
        "en": "DIGITAL PRICE BOARD",
        "ar": "لوحة السعر الرقمية",
    },
    "price_checked": {
        "en": "Checked",
        "ar": "آخر فحص",
    },
    "bar_time": {
        "en": "1m bar",
        "ar": "شمعة 1m",
    },
    "quote_source": {
        "en": "Data",
        "ar": "البيانات",
    },
    "news": {
        "en": "NEWS",
        "ar": "الأخبار",
    },
    "news_engine": {
        "en": "NEWS IMPACT",
        "ar": "تأثير الأخبار",
    },
    "news_risk": {
        "en": "NEWS RISK",
        "ar": "مخاطر الأخبار",
    },
    "headline_bias": {
        "en": "HEADLINE BIAS",
        "ar": "اتجاه العناوين",
    },
    "important_news": {
        "en": "IMPORTANT NEWS",
        "ar": "أهم الأخبار",
    },
    "symbol_news": {
        "en": "Instrument news",
        "ar": "أخبار الأصل",
    },
    "market_news": {
        "en": "Market-wide news",
        "ar": "أخبار السوق العامة",
    },
    "news_none": {
        "en": "No recent news was returned by the free source.",
        "ar": "لم يُرجع المصدر المجاني أخبارًا حديثة حاليًا.",
    },
    "news_note": {
        "en": "News is a risk/context layer only. Headline bias is a simple keyword classification and does not override the technical engine. Free news can be delayed or incomplete.",
        "ar": "الأخبار هنا طبقة للمخاطر والسياق فقط. اتجاه العنوان تصنيف مبسط بالكلمات ولا يلغي المحرك الفني. وقد تتأخر الأخبار المجانية أو تكون غير مكتملة.",
    },
    "published": {
        "en": "Published",
        "ar": "النشر",
    },
    "impact": {
        "en": "Impact",
        "ar": "التأثير",
    },
    "scope": {
        "en": "Scope",
        "ar": "النطاق",
    },
    "market": {
        "en": "Market",
        "ar": "الأصل",
    },
    "target_timeframe": {
        "en": "Target timeframe",
        "ar": "فريم الأهداف",
    },
    "target_timeframe_help": {
        "en": "The selected analysis timeframe controls chart, candles and price levels together.",
        "ar": "فريم التحليل المختار يحدد الشارت والشموع والمستويات السعرية معًا.",
    },
    "chart_tf_global": {
        "en": "Chart timeframe",
        "ar": "فريم الشارت",
    },
    "candle_focus_tf": {
        "en": "Candle focus",
        "ar": "فريم قراءة الشمعة",
    },
    "refresh_every": {
        "en": "Refresh",
        "ar": "التحديث",
    },
    "every_60s": {
        "en": "15s price / 1m signals",
        "ar": "السعر 15ث / الإشارات 1m",
    },
    "calculation_basis": {
        "en": "CALCULATION BASIS",
        "ar": "أساس الحساب",
    },
    "target_formula_note": {
        "en": "Rolling reference range: latest timestamped price +/- 0.15 ATR. Watch range: estimated level +/- 0.30 ATR. Targets use confirmed pivots where available, otherwise ATR projections, with at least 1 ATR spacing. Scenario invalidation: 1.15 ATR from the reference price.",
        "ar": "نطاق مرجعي متجدد: آخر سعر مؤرخ بهامش 0.15 ATR. المراقبة: مستوى تقديري بهامش 0.30 ATR. الأهداف تعتمد على قمم/قيعان مؤكدة عند توفرها، وإلا امتدادات ATR، بفاصل لا يقل عن ATR واحد. إلغاء السيناريو: 1.15 ATR من السعر المرجعي.",
    },
    "data_source_note": {
        "en": "The digital price board checks the selected instrument every 15 seconds. Technical signals are built from 1-minute bars, so they normally change only when a new 1-minute bar arrives. The free data source can still be delayed or temporarily unavailable.",
        "ar": "تفحص لوحة السعر الرقمية الأصل المختار كل 15 ثانية. أما الإشارات الفنية فمبنية على شموع 1 دقيقة، لذلك تتغير عادة عند وصول شمعة دقيقة جديدة. وقد يتأخر مصدر البيانات المجاني أو يتوقف مؤقتًا.",
    },
    "higher_tf_context": {
        "en": "4H CONTEXT",
        "ar": "سياق 4H",
    },
    "action_now": {
        "en": "ACTION NOW",
        "ar": "الإجراء الآن",
    },
    "trade_setup_note": {
        "en": "The chosen timeframe controls chart and levels. Overall bias combines frames; 4H is separate context. Daily/weekly levels describe broader horizons, not minute targets.",
        "ar": "الفريم المختار يحدد الشارت والمستويات. الاتجاه العام يجمع الفريمات، و4H سياق منفصل. المستويات اليومية والأسبوعية لأفق أوسع وليست أهداف دقائق.",
    },
    "overview": {
        "en": "OVERVIEW",
        "ar": "الرئيسية",
    },
    "chart": {
        "en": "CHART",
        "ar": "الشارت",
    },
    "frames": {
        "en": "FRAMES",
        "ar": "الفريمات",
    },
    "paper_log": {
        "en": "PAPER LOG",
        "ar": "سجل الورقي",
    },
    "test": {
        "en": "TEST",
        "ar": "الاختبار",
    },
    "bias": {
        "en": "BIAS",
        "ar": "الاتجاه",
    },
    "strength": {
        "en": "SCORE / 100",
        "ar": "درجة القوة / 100",
    },
    "wave": {
        "en": "WAVE",
        "ar": "الموجة",
    },
    "status": {
        "en": "STATUS",
        "ar": "حالة السوق",
    },
    "signal_age": {
        "en": "SIGNAL AGE",
        "ar": "عمر الإشارة",
    },
    "paused": {
        "en": "PAUSED",
        "ar": "متوقف",
    },
    "paper_trade_map": {
        "en": "PAPER TRADE MAP",
        "ar": "خريطة التداول الورقي",
    },
    "no_entry": {
        "en": "WAIT — No active paper entry",
        "ar": "انتظار — لا توجد منطقة دخول ورقية نشطة",
    },
    "entry": {
        "en": "Entry",
        "ar": "منطقة الدخول",
    },
    "invalidation": {
        "en": "Invalidation",
        "ar": "إلغاء الإشارة",
    },
    "liquidity_zero": {
        "en": "ESTIMATED SUPPORT / RESISTANCE",
        "ar": "الدعم والمقاومة التقديرية",
    },
    "above": {
        "en": "Above",
        "ar": "مقاومة تقديرية",
    },
    "below": {
        "en": "Below",
        "ar": "دعم تقديري",
    },
    "zero_watch": {
        "en": "Price-level watch",
        "ar": "مراقبة المستوى السعري",
    },
    "wave_stage": {
        "en": "Wave stage",
        "ar": "مرحلة الموجة",
    },
    "liquidity_note": {
        "en": "Liquidity is a price-structure proxy, not Level 2 or hidden dealer liquidity.",
        "ar": "السيولة هنا تقدير مبني على هيكل السعر وليست Level 2 أو سيولة صانع السوق المخفية.",
    },
    "quick_frames": {
        "en": "QUICK FRAMES",
        "ar": "الفريمات السريعة",
    },
    "tf": {
        "en": "TF",
        "ar": "الفريم",
    },
    "signal": {
        "en": "Signal",
        "ar": "الإشارة",
    },
    "distance_map": {
        "en": "TARGETS & LEVELS",
        "ar": "الأهداف والمستويات",
    },
    "to_entry": {
        "en": "ENTRY",
        "ar": "الدخول",
    },
    "to_t1": {
        "en": "TARGET 1",
        "ar": "الهدف 1",
    },
    "to_t2": {
        "en": "TARGET 2",
        "ar": "الهدف 2",
    },
    "to_t3": {
        "en": "TARGET 3",
        "ar": "الهدف 3",
    },
    "to_zero": {
        "en": "WATCH RANGE",
        "ar": "نطاق المراقبة",
    },
    "in_zone": {
        "en": "IN ZONE",
        "ar": "داخل المنطقة",
    },
    "last_data": {
        "en": "Last data",
        "ar": "آخر بيانات",
    },
    "chart_timeframe": {
        "en": "Chart timeframe",
        "ar": "فريم الشارت",
    },
    "bars": {
        "en": "Bars",
        "ar": "عدد الشموع",
    },
    "no_chart": {
        "en": "No chart data for this timeframe.",
        "ar": "لا توجد بيانات شارت لهذا الفريم.",
    },
    "liquidity_up": {
        "en": "Estimated resistance",
        "ar": "مقاومة تقديرية",
    },
    "liquidity_down": {
        "en": "Estimated support",
        "ar": "دعم تقديري",
    },
    "zero_chart": {
        "en": "WATCH RANGE",
        "ar": "نطاق المراقبة",
    },
    "entry_chart": {
        "en": "ENTRY",
        "ar": "دخول",
    },
    "timeframe": {
        "en": "Timeframe",
        "ar": "الفريم",
    },
    "strength_score": {
        "en": "Strength Score",
        "ar": "درجة القوة",
    },
    "weight": {
        "en": "Weight",
        "ar": "الوزن",
    },
    "no_open_trade": {
        "en": "No open paper trade for {symbol}.",
        "ar": "لا توجد صفقة ورقية مفتوحة لـ {symbol}.",
    },
    "open": {
        "en": "OPEN",
        "ar": "مفتوحة",
    },
    "current": {
        "en": "CURRENT",
        "ar": "الحالي",
    },
    "running": {
        "en": "RUNNING",
        "ar": "جارية",
    },
    "download_log": {
        "en": "Download Paper Log CSV",
        "ar": "تحميل سجل التداول الورقي CSV",
    },
    "log_wait": {
        "en": "The log will add a trade automatically when the Action Engine produces a paper-entry signal.",
        "ar": "سيتم تسجيل الصفقة تلقائيًا عندما يصدر محرك القرار إشارة دخول ورقية.",
    },
    "log_session": {
        "en": "Current log is session-based for testing. A persistent database can be added after live validation.",
        "ar": "السجل الحالي مؤقت داخل الجلسة للاختبار. سنضيف قاعدة بيانات دائمة بعد التحقق الحي.",
    },
    "direction": {
        "en": "Direction",
        "ar": "الاتجاه",
    },
    "previous": {
        "en": "Previous",
        "ar": "السابق",
    },
    "data_age": {
        "en": "Data age",
        "ar": "عمر البيانات",
    },
    "ny_time": {
        "en": "Current New York time",
        "ar": "الوقت الحالي في نيويورك",
    },
    "last_market_data": {
        "en": "Last market data",
        "ar": "آخر بيانات للسوق",
    },
    "action_engine": {
        "en": "Action Engine",
        "ar": "محرك القرار",
    },
    "session_signal_age": {
        "en": "Session Signal Age",
        "ar": "عمر الإشارة في الجلسة",
    },
    "distance_entry": {
        "en": "Distance to Entry",
        "ar": "المسافة إلى الدخول",
    },
    "distance_zero": {
        "en": "Distance to watch range",
        "ar": "المسافة إلى نطاق المراقبة",
    },
    "test_note": {
        "en": "This tab is retained for paper-testing, threshold tuning and error correction.",
        "ar": "هذا التبويب مخصص للاختبار الورقي وضبط الحدود وتصحيح الأخطاء.",
    },
    "candles": {
        "en": "CANDLES",
        "ar": "الشموع",
    },
    "fast_setup": {
        "en": "FAST LAUNCH SETUP",
        "ar": "إعداد الانطلاقة السريعة",
    },
    "launch_signal": {
        "en": "LAUNCH",
        "ar": "الانطلاقة",
    },
    "candle_pattern": {
        "en": "Candle pattern",
        "ar": "نموذج الشمعة",
    },
    "structure": {
        "en": "Structure",
        "ar": "هيكل السعر",
    },
    "volume_state": {
        "en": "Volume",
        "ar": "الحجم",
    },
    "momentum_state": {
        "en": "Momentum",
        "ar": "الزخم",
    },
    "volume_ratio": {
        "en": "Volume ratio",
        "ar": "نسبة الحجم",
    },
    "launch_note": {
        "en": "Candlestick patterns are used only with structure, momentum and volume. A hammer or doji alone is never treated as a trade signal.",
        "ar": "تستخدم نماذج الشموع مع هيكل السعر والزخم والحجم فقط. الهامر أو الدوجي وحدهما لا يعتبران إشارة دخول.",
    },
}

def tr(key):
    if key == "chart_tf_global":
        return "فريم التحليل المختار" if AR else "Selected analysis timeframe"
    if key == "trade_setup_note":
        return (f"الرسم والأهداف والشموع على فريم {analysis_timeframe}. اتجاه النجمة يجمع الفريمات كلها؛ مستويات الأهداف مشروطة باستمرار ذلك الاتجاه."
                if AR else f"Chart, targets and candle focus use {analysis_timeframe}. Stars combine all timeframes; target levels are conditional on that overall direction.")
    if key == "target_formula_note":
        return ("ATR14 من الشموع المكتملة للفريم المختار، والنطاق المرجعي حول آخر سعر مؤرخ. تستخدم الأهداف قممًا/قيعانًا مؤكدة أو مراجع 1 و2 و3 ATR، بفاصل ATR واحد على الأقل."
                if AR else "Closed-bar ATR14 and a rolling reference range around the latest timestamped price on the selected timeframe. Targets use confirmed pivots or 1/2/3 ATR references, at least one ATR apart.")
    if key == "every_60s":
        return f"{PRICE_BOARD_REFRESH_SECONDS}ث" if AR else f"{PRICE_BOARD_REFRESH_SECONDS}s"
    return TEXT[key]["ar" if AR else "en"]


SIGNAL_DISPLAY = {
    "CALL": "كول (CALL)" if AR else "CALL",
    "PUT": "بوت (PUT)" if AR else "PUT",
    "WAIT": "انتظار" if AR else "WAIT",
}

STATUS_DISPLAY = {
    "LIVE": "جلسة عادية · بيانات حديثة" if AR else "REGULAR · RECENT",
    "POST-MARKET": "بعد الإغلاق" if AR else "POST-MARKET",
    "PRE-MARKET": "قبل الافتتاح" if AR else "PRE-MARKET",
    "CLOSED": "مغلق" if AR else "CLOSED",
    "WEEKEND": "عطلة نهاية الأسبوع" if AR else "WEEKEND",
    "HOLIDAY": "عطلة سوق" if AR else "HOLIDAY",
    "STALE": "بيانات متأخرة" if AR else "STALE",
    "UNKNOWN": "غير معروف" if AR else "UNKNOWN",
}

WAVE_DISPLAY_AR = {
    "CONFIRMED CALL": "كول مؤكد",
    "CONFIRMED PUT": "بوت مؤكد",
    "START CALL": "بداية موجة كول",
    "START PUT": "بداية موجة بوت",
    "ZERO WATCH": "مراقبة المستوى السعري",
    "CALL WEAKENING": "ضعف موجة الكول",
    "PUT WEAKENING": "ضعف موجة البوت",
    "CALL ACTIVE": "موجة كول نشطة",
    "PUT ACTIVE": "موجة بوت نشطة",
    "CALL WATCH": "مراقبة كول",
    "PUT WATCH": "مراقبة بوت",
    "WAIT": "انتظار",
}

ACTION_DISPLAY_AR = {
    "FRAME CONFLICT — WAIT": "الفريم المختار لا يؤكد الاتجاه العام — انتظار",
    "PAPER CALL ENTRY": "دخول كول ورقي",
    "PAPER PUT ENTRY": "دخول بوت ورقي",
    "CONFIRMED CALL — WAIT FOR ENTRY": "كول مؤكد — انتظر منطقة الدخول",
    "CONFIRMED PUT — WAIT FOR ENTRY": "بوت مؤكد — انتظر منطقة الدخول",
    "LAST SESSION: CONFIRMED CALL": "الجلسة السابقة: كول مؤكد",
    "LAST SESSION: CONFIRMED PUT": "الجلسة السابقة: بوت مؤكد",
    "PAPER CALL WATCH": "مراقبة كول ورقي",
    "PAPER PUT WATCH": "مراقبة بوت ورقي",
    "LAST SESSION: START CALL": "الجلسة السابقة: بداية كول",
    "LAST SESSION: START PUT": "الجلسة السابقة: بداية بوت",
    "STRONG PAPER CALL": "كول ورقي قوي",
    "STRONG PAPER PUT": "بوت ورقي قوي",
    "CALL ACTIVE — WAIT FOR PULLBACK": "الكول نشط — انتظر التراجع للدخول",
    "PUT ACTIVE — WAIT FOR PULLBACK": "البوت نشط — انتظر الارتداد للدخول",
    "CALL WATCH": "مراقبة كول",
    "PUT WATCH": "مراقبة بوت",
    "PROTECT PAPER PROFIT / NO NEW ENTRY": "احمِ الربح الورقي / لا دخول جديد",
    "WAIT FOR REVERSAL CONFIRMATION": "انتظر تأكيد الانعكاس",
    "CALL WATCH — WAIT FOR CONFIRMATION": "مراقبة كول — انتظر التأكيد",
    "PUT WATCH — WAIT FOR CONFIRMATION": "مراقبة بوت — انتظر التأكيد",
    "WAIT — NO PAPER TRADE": "انتظار — لا صفقة ورقية",
    "DO NOT CHASE — CALL WAVE EXTENDED": "لا تطارد السعر — موجة الكول ممتدة",
    "DO NOT CHASE — PUT WAVE EXTENDED": "لا تطارد السعر — موجة البوت ممتدة",
    "EARLY PAPER CALL WATCH": "مراقبة مبكرة لكول ورقي",
    "EARLY PAPER PUT WATCH": "مراقبة مبكرة لبوت ورقي",
    "FAST SETUP CONFLICT — WAIT": "تعارض في الانطلاقة السريعة — انتظار",
}

def display_signal(value):
    return SIGNAL_DISPLAY.get(value, value)

def display_status(value):
    return STATUS_DISPLAY.get(value, value)

def display_wave(value):
    if AR:
        return WAVE_DISPLAY_AR.get(value, value)
    return "PRICE LEVEL WATCH" if value == "ZERO WATCH" else value

def display_action(value):
    if AR:
        return ACTION_DISPLAY_AR.get(value, value)
    return value



def hunter_range_card(label, lower, upper, detail=""):
    """Separate bounds and isolate Latin numerals from Arabic bidi layout."""
    low_label, high_label = ("الحد الأدنى", "الحد الأعلى") if AR else ("Lower bound", "Upper bound")
    render_html(f"""<div class="hunter-range">
      <strong>{html.escape(label)}</strong>
      <div>{low_label}: <bdi dir="ltr">{lower:,.2f}</bdi></div>
      <div>{high_label}: <bdi dir="ltr">{upper:,.2f}</bdi></div>
      <small>{html.escape(detail)}</small>
    </div>""")


def hunter_position_note(direction, price, lower, upper, stop, local_signal, status, ar=True):
    if status not in HUNTER_ACTIVE_STATES:
        return ("السوق مغلق أو البيانات متأخرة: هذه خريطة آخر بيانات متاحة، وليست إشارة دخول حية."
                if ar else "Market closed or data delayed: last available setup, not a live entry signal.")
    if direction not in ("CALL", "PUT"):
        return "انتظار: لا يوجد اتجاه واضح للدخول." if ar else "Wait: no clear entry direction."
    if stop is not None and ((direction == "CALL" and price <= stop) or (direction == "PUT" and price >= stop)):
        return "السعر تجاوز مستوى الإلغاء: لا تعتمد هذه الخريطة للدخول." if ar else "Price crossed invalidation: do not use this setup for entry."
    if local_signal != direction:
        return "الفريم المختار لا يؤكد الاتجاه العام: انتظار." if ar else "Selected timeframe does not confirm overall direction: wait."
    if lower <= price <= upper:
        return "السعر داخل نطاق الدخول المحتمل؛ يلزم تأكيد الإشارة." if ar else "Price is inside the potential entry range; signal confirmation is still required."
    if direction == "CALL" and price > upper:
        return "السعر أعلى من نطاق الدخول: انتظار تراجع إليه، دون مطاردة السعر." if ar else "Price is above entry: wait for a pullback; do not chase."
    if direction == "PUT" and price < lower:
        return "السعر أسفل نطاق الدخول: انتظار ارتداد إليه، دون مطاردة السعر." if ar else "Price is below entry: wait for a rebound; do not chase."
    return "السعر خارج نطاق الدخول: انتظار الوصول إليه ثم إعادة تقييم الإشارة." if ar else "Price is outside entry: wait for the range, then reassess the signal."



st.markdown("""<style>
[data-testid="stMetricValue"], [data-testid="stMetricValue"] > div,
[data-testid="stMetricLabel"], [data-testid="stMetricLabel"] p {
    white-space: normal !important; overflow: visible !important;
    text-overflow: clip !important; overflow-wrap: anywhere;
}
[data-testid="stMetricValue"] {font-size: 1.45rem !important; line-height: 1.5;}
.hunter-range {border: 1px solid #8794a655; border-radius: 12px; padding: 18px;
    margin-bottom: 12px; background: var(--secondary-background-color); line-height: 1.9;}
.hunter-range bdi {display: inline-block; font-size: 1.25rem; font-variant-numeric: tabular-nums;}
.hunter-range small {display: block;}
</style>""", unsafe_allow_html=True)

# RTL for Arabic
if AR:
    st.markdown(
        """
        <style>
        .block-container { direction: rtl; }
        .qt-header, .qt-action { direction: rtl; text-align: right; }
        div[data-testid="stMetricLabel"],
        div[data-testid="stMetricValue"],
        .stMarkdown,
        .stCaptionContainer {
            text-align: right;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ============================================================
# HEADER / CONTROLS
# ============================================================

st.markdown(
    f"""
    <div class="qt-header">
        <div>
            <div class="qt-brand">{APP_NAME}</div>
            <div class="qt-sub">{tr("subtitle")}</div>
        </div>
        <div>
            <span class="qt-badge">{tr("paper_only")}</span>
            <span class="qt-badge">{tr("wave_engine")}</span>
            <span class="qt-badge">{tr("auto_refresh")}</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("""<style>
.stMainBlockContainer {max-width:1500px; padding-top:1rem;}
[data-testid="stMetricValue"] {font-size:clamp(1.05rem, 2.2vw, 1.5rem) !important;}
.qt-price-main {font-size:clamp(2.3rem, 7vw, 5.5rem) !important; overflow-wrap:anywhere;}
[data-testid="stRadio"] [role="radiogroup"] {flex-wrap:wrap; gap:.5rem;}
@media (max-width: 767px) {
  .block-container, .stMainBlockContainer {padding-left:.7rem !important; padding-right:.7rem !important;}
  [data-testid="stHorizontalBlock"] {flex-wrap:wrap !important; gap:.65rem !important;}
  [data-testid="stColumn"] {width:100% !important; flex:1 1 100% !important; min-width:0 !important;}
  .qt-price-board {display:flex !important; flex-direction:column !important; gap:1rem !important; padding:1rem !important;}
  .qt-header {flex-wrap:wrap !important; gap:.7rem !important;}
  .qt-brand {font-size:1.55rem !important;}
  .hunter-range {padding:.8rem !important;}
  [data-testid="stPlotlyChart"] {max-width:100%;}
}
</style>""", unsafe_allow_html=True)

# The SAME complete instrument list is accessible to both roles.
with st.spinner("جار تحديث قائمة الأسهم..." if AR else "Updating instruments..."):
    hunter_universe = hunter_download_universe(tuple(SYMBOLS.values()))
symbol, hunter_star_states = hunter_render_watchlist(hunter_universe, FRAME_WEIGHTS)
# View navigation belongs to this authenticated session, not global owner settings.
analysis_timeframe = hunter_select_analysis_timeframe(hunter_settings["target_timeframe"])
chart_timeframe = target_timeframe = candle_focus_timeframe = analysis_timeframe
paper_scope = f"{symbol} · {analysis_timeframe}"

ticker = SYMBOLS[symbol]


# ============================================================
# DOWNLOAD / PREP DATA
# ============================================================

# Reuse the star scanner snapshot so detail and star cannot disagree due to separate fetches.
minute_data = hunter_universe[ticker]["minute"]
hour_data = hunter_universe[ticker]["hour"]
daily_data = hunter_universe[ticker]["daily"]
weekly_data = hunter_universe[ticker]["weekly"]

if minute_data.empty:
    st.error(
        "تعذر جلب بيانات السوق من المصدر. ستتم إعادة المحاولة تلقائيًا؛ قد يكون هناك تقييد للطلبات. / Market feed unavailable; retrying automatically with backoff."
    )
    st.stop()


# ============================================================
# CURRENT STATE
# ============================================================

current_price = float(
    minute_data["Close"].iloc[-1]
)

last_update = minute_data.index[-1]
last_ts_ny = normalize_timestamp_to_ny(
    last_update
)

market_status, now_ny = get_market_status(
    last_update, ticker
)

if minute_data.attrs.get("feed_unavailable"):
    market_status = "STALE"

data_age_minutes = max(
    0.0,
    (now_ny - last_ts_ny).total_seconds() / 60.0
)

# One timestamped price for the board, distances, targets and paper tracking.
board_price = current_price
prior_daily = daily_data.loc[[pd.Timestamp(stamp).date() < now_ny.date() for stamp in daily_data.index]]
previous_close = float(prior_daily["Close"].iloc[-1]) if not prior_daily.empty else None

if previous_close is not None and previous_close != 0:
    board_change = board_price - previous_close
    board_change_pct = (
        board_change / previous_close * 100
    )
else:
    board_change = 0.0
    board_change_pct = 0.0

st.caption((f"الإصدار {HUNTER_VERSION} · المصدر: Yahoo Finance · آخر شمعة سعر: {last_ts_ny:%Y-%m-%d %H:%M} ET · عمر البيانات: {data_age_minutes:.1f} دقيقة. التحديث دوري، وليس بث صفقات لحظيًا."
            if AR else f"Version {HUNTER_VERSION} · Yahoo Finance · Last price bar: {last_ts_ny:%Y-%m-%d %H:%M} ET · Age: {data_age_minutes:.1f} min. Polling, not a tick stream."))
if ticker == "^GSPC":
    st.info("SPX مؤشر نقدي: خارج الجلسة العادية تظهر آخر بياناته المتاحة؛ لا نستبدله بأسعار العقود المستقبلية." if AR else "SPX cash index: outside regular hours the last available index data is shown; futures are not substituted.")
elif market_status in {"PRE-MARKET", "POST-MARKET"}:
    st.info("جلسة ممتدة: الأسعار حسب توافر المصدر؛ قد تكون التداولات أقل والسيولة أضعف." if AR else "Extended session: source availability varies and liquidity may be lower.")
if market_status not in HUNTER_ACTIVE_STATES:
    st.warning("هذه بيانات مرجعية؛ لا توجد إشارة دخول حديثة في حالة الإغلاق أو تأخر المصدر." if AR else "Reference data: no fresh entry signal while closed or the feed is stale.")

previous_board_key = f"previous_board_price_{symbol}"
previous_board_price = st.session_state.get(
    previous_board_key,
    board_price,
)

refresh_move = board_price - previous_board_price

st.session_state[
    previous_board_key
] = board_price

if refresh_move > 0:
    board_direction = "up"
    board_arrow = "▲"
elif refresh_move < 0:
    board_direction = "down"
    board_arrow = "▼"
else:
    if board_change > 0:
        board_direction = "up"
        board_arrow = "▲"
    elif board_change < 0:
        board_direction = "down"
        board_arrow = "▼"
    else:
        board_direction = "flat"
        board_arrow = "•"

price_changed_class = (
    "price-changed"
    if abs(refresh_move) > 0
    else ""
)

symbol_news = hunter_news_snapshot(
    ticker,
    limit=10,
    scope="SYMBOL",
)

market_news_spy = hunter_news_snapshot(
    "SPY",
    limit=8,
    scope="MARKET",
)

market_news_qqq = hunter_news_snapshot(
    "QQQ",
    limit=8,
    scope="MARKET",
)

combined_news = merge_news(
    symbol_news,
    market_news_spy + market_news_qqq,
    now_ny,
)

news_state = build_news_state(
    combined_news
)
if not combined_news:
    news_state["risk"] = "UNKNOWN"

timeframes = hunter_timeframes(minute_data, hour_data, daily_data, weekly_data)
timeframes = {tf: hunter_completed_frame(df, tf, now_ny) for tf,df in timeframes.items()}

results = {
    tf: analyze_timeframe(df)
    for tf, df in timeframes.items()
}

higher_tf_context = results["4H"]["signal"]

previous_results = build_previous_results(
    timeframes
)

master_signal, signal_strength, direction_score = (
    compute_master(results)
)

previous_master, _, previous_direction_score = (
    compute_master(previous_results)
)

launch_engine = compute_launch_engine(
    timeframes
)

launch_signal = launch_engine["signal"]
launch_strength = launch_engine["strength"]
launch_score = launch_engine["score"]

target_data = hunter_completed_frame(timeframes[target_timeframe], target_timeframe, now_ny)
# The selected chart and candle focus use the same completed-bar sample as the targets.
timeframes[target_timeframe] = target_data
selected_frame_signal = analyze_timeframe(target_data)["signal"]
overall_signal, overall_strength = master_signal, signal_strength
# Local scenario is explicit; overall trend remains context and watchlist direction.
master_signal = selected_frame_signal
signal_strength = round(abs(results[target_timeframe]["score"])/6*100)
target_setup = hunter_target_levels(target_data, selected_frame_signal, current_price)
if target_setup is None:
    st.warning("لا توجد شموع مكتملة كافية لحساب مستويات هذا الفريم. اختر فريمًا آخر." if AR
               else "Insufficient completed bars for this timeframe. Select another timeframe.")
    st.stop()
st.caption((f"بداية آخر شمعة تحليل مكتملة: {target_data.index[-1]} · الفريم: {target_timeframe}"
            if AR else f"Latest completed analysis bar starts: {target_data.index[-1]} · Frame: {target_timeframe}"))
current_atr = target_setup["atr"]
entry_anchor = target_setup["anchor"]
entry_low, entry_high = target_setup["entry_low"], target_setup["entry_high"]
liquidity_above, liquidity_below = target_setup["liquidity_above"], target_setup["liquidity_below"]
zero_low, zero_high = target_setup["zero_low"], target_setup["zero_high"]
target1, target2, target3 = target_setup["targets"]
invalidation = target_setup["invalidation"]
target_timing = hunter_timing_estimate(
    target_data, target_timeframe, master_signal, current_price, target_setup["targets"],
    market_status, invalidation=invalidation, local_signal=selected_frame_signal,
)


wave_stage = determine_wave_stage(
    results=results,
    previous_results=previous_results,
    master_signal=master_signal,
    previous_master=previous_results[target_timeframe]["signal"],
    signal_strength=signal_strength,
    current_price=current_price,
    zero_low=zero_low,
    zero_high=zero_high,
)

# A signal describes closed-bar direction. Entry additionally needs fresh data and momentum.
local_score = results[target_timeframe]["score"]
local_momentum = float(target_data["Close"].iloc[-1] - target_data["Close"].iloc[-4])
side = 1 if selected_frame_signal == "CALL" else -1 if selected_frame_signal == "PUT" else 0
extension = abs(current_price-float(ema(target_data["Close"],9).iloc[-1])) / current_atr
if market_status not in HUNTER_ACTIVE_STATES:
    action_text = "WAIT — NO PAPER TRADE"
elif not side:
    action_text = "WAIT — NO PAPER TRADE"
elif overall_signal not in (selected_frame_signal, "WAIT"):
    action_text = "FRAME CONFLICT — WAIT"
elif side*local_momentum <= 0 or side*local_score < 4 or extension > 1.5:
    action_text = selected_frame_signal + " WATCH — WAIT FOR CONFIRMATION"
else:
    action_text = "PAPER " + selected_frame_signal + " ENTRY"

st.info((f"الفريم {target_timeframe}: {display_signal(selected_frame_signal)} · توافق الفريمات: {display_signal(overall_signal)} ({overall_strength}/100). الأهداف سيناريو متجدد من آخر سعر متاح، وليست أوامر أو أرباحًا مضمونة."
         if AR else f"{target_timeframe}: {selected_frame_signal} · Multi-frame context: {overall_signal} ({overall_strength}/100). Targets are rolling scenarios from the latest price, not orders or guaranteed returns."))
st.caption("تُثبت قراءة الاتجاه بعد اكتمال الشمعة. فريمات 6 و8 ساعات تُختصر عند نهاية كل جلسة؛ لا تدمج الإغلاق الليلي. نطاق المراقبة مستوى سعري تقديري وليس قياس سيولة فعلية."
           if AR else "Direction uses completed bars. Six/eight-hour bars truncate at each session boundary; overnight closures are not merged. Watch zones are price estimates, not measured order-book liquidity.")

signal_age_minutes = get_session_signal_age(
    symbol=paper_scope,
    master_signal=master_signal,
    market_status=market_status,
    now_ny=now_ny,
)

entry_distance = distance_to_zone(
    current_price,
    entry_low,
    entry_high,
)

zero_distance = distance_to_zone(
    current_price,
    zero_low,
    zero_high,
)

t1_distance = directional_distance(
    current_price,
    target1,
    master_signal,
)

t2_distance = directional_distance(
    current_price,
    target2,
    master_signal,
)

t3_distance = directional_distance(
    current_price,
    target3,
    master_signal,
)

maybe_open_paper_trade(
    symbol=paper_scope,
    action_text=action_text,
    now_ny=now_ny,
    current_price=current_price,
    target1=target1,
    target2=target2,
    target3=target3,
    invalidation=invalidation,
)

update_paper_trade(
    symbol=paper_scope,
    now_ny=now_ny,
    current_price=current_price,
)


# ============================================================
# SELECTED INSTRUMENT / DIGITAL PRICE BOARD
# ============================================================
if monitor_requested():
    render_monitor(
        symbol=symbol,
        frame=target_timeframe,
        price=current_price,
        signal=selected_frame_signal,
        strength=signal_strength,
        wave=wave_stage,
        entry_low=entry_low,
        entry_high=entry_high,
        watch_low=zero_low,
        watch_high=zero_high,
        targets=[target1, target2, target3],
        invalidation=invalidation,
        market_status=market_status,
        updated_at=last_ts_ny.strftime("%Y-%m-%d %H:%M:%S ET"),
        data_age=data_age_minutes,
        action=display_action(action_text),
    )

    # Calculations and paper-trade updates above have already run.
    # Do not render the remaining detailed page in monitor mode.
    st.stop()

monitor_open_button(symbol, target_timeframe)
board_checked_text = now_ny.strftime(
    "%H:%M:%S ET"
)

bar_time_text = last_ts_ny.strftime(
    "%H:%M ET"
)

price_change_text = (
    f"{board_arrow} {board_change:+,.2f} "
    f"({board_change_pct:+.2f}%)"
)
if previous_close is None:
    price_change_text = "تغير الإغلاق السابق غير متاح" if AR else "Previous-close change unavailable"

render_html(
    f"""
    <div class="qt-price-board {board_direction} {price_changed_class}">
      <div>
        <div class="qt-market-label">{html.escape(tr("price_board"))}</div>
        <div class="qt-price-symbol">★ {html.escape(symbol)}</div>
        <div class="qt-price-name">{html.escape(MARKET_NAMES[symbol])}</div>
      </div>
      <div>
        <div class="qt-price-main">{board_price:,.2f}</div>
        <div class="qt-price-change {board_direction}">{html.escape(price_change_text)}</div>
      </div>
      <div class="qt-price-meta">
        <div class="qt-price-status">{html.escape(display_status(market_status))}</div>
        <div>{html.escape(tr("price_checked"))}: {html.escape(board_checked_text)}</div>
        <div>{html.escape(tr("bar_time"))}: {html.escape(bar_time_text)}</div>
        <div>{html.escape(tr("quote_source"))}: Yahoo Finance · 1m · Polling</div>
      </div>
    </div>
    """
)


# ============================================================
# NEWS IMPACT STRIP
# ============================================================

top_news = news_state["top"]

if top_news is not None:
    top_age = top_news["age_minutes"]

    if top_age is None:
        age_text = ""
    elif top_age < 60:
        age_text = (
            f"{top_age:.0f}m"
            if not AR
            else f"منذ {top_age:.0f}د"
        )
    else:
        hours = top_age / 60.0
        age_text = (
            f"{hours:.1f}h"
            if not AR
            else f"منذ {hours:.1f}س"
        )

    impact_label = top_news["impact"]
    bias_label = top_news["headline_bias"]

    if AR:
        impact_display = {
            "HIGH": "مرتفع",
            "MEDIUM": "متوسط",
            "LOW": "منخفض",
        }.get(impact_label, impact_label)

        bias_display = {
            "BULLISH": "إيجابي",
            "BEARISH": "سلبي",
            "NEUTRAL": "محايد",
        }.get(bias_label, bias_label)
    else:
        impact_display = impact_label
        bias_display = bias_label

    top_news_display = (
        arabic_news_brief(top_news)
        if AR
        else top_news["title"]
    )

    scope_display = (
        "السوق"
        if AR and top_news["scope"] == "MARKET"
        else (
            symbol
            if AR and top_news["scope"] == "SYMBOL"
            else top_news["scope"]
        )
    )

    render_html(
        f"""
        <div class="qt-news-strip {impact_label.lower()}">
          <div>
            <div class="qt-news-kicker">{html.escape(tr("important_news"))}</div>
            <div class="qt-news-meta">
              {html.escape(tr("impact"))}: {html.escape(str(impact_display))} •
              {html.escape(tr("headline_bias"))}: {html.escape(str(bias_display))}
            </div>
          </div>
          <div>
            <div class="qt-news-headline">• {html.escape(top_news_display)}</div>
            <div class="qt-news-meta">
              {html.escape(str(top_news["publisher"]))} • {html.escape(age_text)} • {html.escape(str(scope_display))}
            </div>
          </div>
        </div>
        """
    )
else:
    st.info(
        tr("news_none")
    )


# ============================================================
# ACTION CARD
# ============================================================

if AR:
    action_detail = (
        f"{symbol} • {display_status(market_status)} • "
        f"الاتجاه {display_signal(master_signal)} • "
        f"قوة الاتجاه {signal_strength}/100 • "
        f"الموجة {display_wave(wave_stage)} • "
        f"الانطلاقة {display_signal(launch_signal)} {launch_strength}/100 • "
        f"مخاطر الأخبار {news_state['risk']}"
    )
else:
    action_detail = (
        f"{symbol} • {display_status(market_status)} • "
        f"Bias {display_signal(master_signal)} • "
        f"Direction score {signal_strength}/100 • "
        f"Wave {display_wave(wave_stage)} • "
        f"Launch {display_signal(launch_signal)} {launch_strength}/100 • "
        f"News risk {news_state['risk']}"
    )

displayed_action_text = display_action(action_text)

render_html(
    f"""
    <div class="qt-action">
      <div class="qt-action-sub">{html.escape(tr("action_now"))}</div>
      <div class="qt-action-title">{html.escape(displayed_action_text)}</div>
      <div class="qt-action-sub">
        {html.escape(action_detail)} •
        {html.escape(tr("higher_tf_context"))}: {html.escape(display_signal(higher_tf_context))}
      </div>
    </div>
    """
)



# ============================================================
# CALCULATION BASIS / REFRESH TRANSPARENCY
# ============================================================

basis_cols = st.columns(
    6,
    gap="small",
)

with basis_cols[0]:
    st.metric(
        tr("chart_tf_global"),
        chart_timeframe,
    )

with basis_cols[1]:
    st.metric(
        tr("target_timeframe"),
        target_timeframe,
    )

with basis_cols[2]:
    st.metric(
        tr("candle_focus_tf"),
        candle_focus_timeframe,
    )

with basis_cols[3]:
    st.metric(
        tr("higher_tf_context"),
        display_signal(higher_tf_context),
    )

with basis_cols[4]:
    st.metric(
        tr("refresh_every"),
        tr("every_60s"),
    )

with basis_cols[5]:
    st.metric(
        tr("data_age"),
        f"{data_age_minutes:,.1f}m",
    )

st.caption(
    tr("trade_setup_note")
)

if IS_ADMIN:
    st.caption(tr("target_formula_note"))

if IS_ADMIN:
    st.caption(tr("data_source_note"))

# ============================================================
# MAIN TABS
# ============================================================

# One continuous page. Context aliases preserve section scoping without navigation tabs.
tab_overview = tab_chart = tab_candles = tab_news = tab_frames = tab_log = tab_test = nullcontext()

# ============================================================
# OVERVIEW
# ============================================================

with tab_overview:

    summary = st.columns(4, gap="small")
    summary[0].metric(symbol, f"{current_price:,.2f}")
    summary[1].metric("توافق الفريمات" if AR else "Multi-frame context", display_signal(overall_signal))
    summary[2].metric("قوة الفريم المختار / 100" if AR else "Selected-frame score / 100", f"{signal_strength}/100")
    summary[3].metric(tr("wave_stage"), display_wave(wave_stage))

    context = st.columns(4, gap="small")
    context[0].metric("فريم التحليل" if AR else "Analysis timeframe", target_timeframe)
    context[1].metric("اتجاه الفريم المختار" if AR else "Selected frame bias", display_signal(selected_frame_signal))
    context[2].metric(f"ATR {target_timeframe}", f"{current_atr:,.2f}")
    context[3].metric(tr("higher_tf_context"), display_signal(higher_tf_context))
    st.caption("درجة القوة تقييم للمؤشرات من 100، وليست احتمال نجاح الصفقة."
               if AR else "Score rates indicators out of 100; it is not a trade success probability.")
    st.info(hunter_position_note(master_signal, current_price, entry_low, entry_high,
                                invalidation, overall_signal if overall_signal != "WAIT" else selected_frame_signal, market_status, AR))
    st.caption(f"{tr('status')}: {display_status(market_status)} · {tr('last_data')}: "
               f"{last_ts_ny.strftime('%Y-%m-%d %H:%M:%S ET')}")

    left, middle, right = st.columns(
        [1.0, 1.0, 1.15],
        gap="small",
    )

    with left:
        st.markdown(f"##### {tr('paper_trade_map')}")

        st.write(("سيناريو مستويات الأصل الأساسي — " if AR else "Underlying price scenario — ") + target_timeframe)
        st.write(("تظهر حدود الدخول والأهداف والإلغاء أدناه، وعلى تبويب الشارت."
                  if AR else "Entry bounds, targets and invalidation appear below and on the chart tab."))
        st.caption("الأسعار تخص الأصل الأساسي؛ ليست أسعار عقود الخيارات أو أرباحها."
                   if AR else "These are underlying prices, not option premiums or profits.")
        st.write(f"**{tr('news_risk')}:** " + ({"HIGH": "مرتفع", "MEDIUM": "متوسط", "LOW": "منخفض", "UNKNOWN":"غير متاح"}.get(news_state["risk"], news_state["risk"]) if AR else news_state["risk"]))

    with middle:
        st.markdown(f"##### {tr('liquidity_zero')}")

        st.write(
            f"**{tr('above')}:** "
            f"{liquidity_above:,.2f}"
        )

        st.write(
            f"**{tr('below')}:** "
            f"{liquidity_below:,.2f}"
        )

        st.caption("نطاق المراقبة حول مستوى سعري تقديري، ولا يثبت انعدام الزخم أو حدوث انعكاس."
                   if AR else "The watch range surrounds an estimated price level; it does not establish zero momentum or a reversal.")

        st.write(
            f"**{tr('wave_stage')}:** {display_wave(wave_stage)}"
        )

        st.caption(
            tr("liquidity_note")
        )

    with right:
        st.markdown(f"##### {tr('quick_frames')}")

        quick_frames = [
            "1m", "3m", "5m",
            "15m", "30m",
            "1H", "4H", "Daily",
        ]

        q_rows = []

        for tf in quick_frames:
            q_rows.append({
                tr("tf"): tf,
                tr("signal"): display_signal(results[tf]["signal"]),
                "RSI": round(
                    results[tf]["rsi"], 1
                ),
            })

        hunter_dataframe(
            pd.DataFrame(q_rows),
            width="stretch",
            hide_index=True,
            height=280,
        )

    st.markdown(
        f"##### {tr('distance_map')} — {target_timeframe}"
    )

    range_cols = st.columns(2, gap="small")
    with range_cols[0]:
        if master_signal == "WAIT":
            st.info(tr("no_entry"))
        else:
            hunter_range_card(tr("entry"), entry_low, entry_high,
                              (f"المسافة إلى النطاق: {entry_distance:,.2f} نقطة" if AR else f"Distance to range: {entry_distance:,.2f} points"))
    with range_cols[1]:
        hunter_range_card(tr("to_zero"), zero_low, zero_high,
                          (f"عرض النطاق: {zero_high-zero_low:,.2f} نقطة" if AR else f"Range width: {zero_high-zero_low:,.2f} points"))
    target_cols = st.columns(3, gap="small")
    for column, number, target in zip(target_cols, (1, 2, 3), (target1, target2, target3)):
        with column:
            st.metric(tr(f"to_t{number}"), "—" if target is None else f"{target:,.2f}")
            if target is not None:
                distance = target-current_price
                side = ("أعلى السعر" if distance > 0 else "أسفل السعر" if distance < 0 else "عند السعر") if AR else ("above price" if distance > 0 else "below price" if distance < 0 else "at price")
                st.caption(f"{abs(distance):,.2f} {'نقطة' if AR else 'points'} — {side}")
    st.write(f"**{tr('invalidation')}:** " + ("—" if invalidation is None else f"{invalidation:,.2f}"))
    st.caption("هذه أهداف مرجعية قابلة لإعادة الحساب، وليست وعودًا بالوصول."
               if AR else "These reference targets can recalculate; reaching them is not guaranteed.")

    source_names = {"pivot": "قمة/قاع مؤكد" if AR else "Confirmed pivot",
                    "atr": "مرجع ATR" if AR else "ATR reference"}
    if target_setup["sources"]:
        st.caption(" · ".join(f"T{i}: {source_names[reason]}" for i, reason in enumerate(target_setup["sources"], 1)))
    st.caption((f"اتجاه الفريم المختار: {display_signal(selected_frame_signal)} · ATR {target_timeframe}: {current_atr:,.2f}"
                if AR else f"Selected timeframe direction: {selected_frame_signal} · ATR {target_timeframe}: {current_atr:,.2f}"))
    hunter_render_timing(target_timing, target_timeframe)
    st.caption(
        f"{tr('last_data')}: "
        f"{last_ts_ny.strftime('%Y-%m-%d %H:%M:%S ET')}"
    )


# ============================================================
# CHART
# ============================================================

with tab_chart:
    st.divider()
    st.subheader(tr("chart"))

    chart_left, chart_right = st.columns(
        [1.0, 4.0],
        gap="small",
    )

    with chart_left:
        st.metric(
            tr("chart_tf_global"),
            chart_timeframe,
        )

        st.metric(
            tr("target_timeframe"),
            target_timeframe,
        )

        candles_to_show = hunter_settings["candles_to_show"]
        st.caption(f"{tr('bars')}: {candles_to_show}")

    chart_df = timeframes[
        chart_timeframe
    ].tail(candles_to_show)

    with chart_right:
        if chart_df.empty:
            st.info(
                tr("no_chart")
            )

        else:
            fig = go.Figure(
                data=[
                    go.Candlestick(
                        x=chart_df.index,
                        open=chart_df["Open"],
                        high=chart_df["High"],
                        low=chart_df["Low"],
                        close=chart_df["Close"],
                        name=symbol,
                    )
                ]
            )

            fig.add_hline(
                y=liquidity_above,
                line_dash="dot",
                annotation_text=tr("liquidity_up"),
            )

            fig.add_hline(
                y=liquidity_below,
                line_dash="dot",
                annotation_text=tr("liquidity_down"),
            )

            fig.add_hrect(
                y0=zero_low,
                y1=zero_high,
                opacity=0.10,
                line_width=0,
                annotation_text=tr("zero_chart"),
            )

            fig.add_hrect(
                y0=entry_low,
                y1=entry_high,
                opacity=0.08,
                line_width=0,
                annotation_text=tr("entry_chart"),
            )

            if target1 is not None:
                fig.add_hline(
                    y=target1,
                    line_dash="dot",
                    annotation_text="T1",
                )
                fig.add_hline(
                    y=target2,
                    line_dash="dot",
                    annotation_text="T2",
                )
                fig.add_hline(
                    y=target3,
                    line_dash="dot",
                    annotation_text="T3",
                )

            if invalidation is not None:
                fig.add_hline(
                    y=invalidation,
                    line_dash="dash",
                    annotation_text=tr("invalidation"),
                )

            chart_launch = analyze_launch_frame(
                chart_df
            )

            chart_pattern = chart_launch["candle"]["pattern"]

            if (
                chart_pattern != "NONE"
                and not chart_df.empty
            ):
                fig.add_annotation(
                    x=chart_df.index[-1],
                    y=float(chart_df["High"].iloc[-1]),
                    text=chart_pattern,
                    showarrow=True,
                    arrowhead=2,
                    yshift=14,
                )

            fig.update_layout(
                template="plotly_dark" if st.session_state["hunter_theme"] == "dark" else "plotly_white",
                paper_bgcolor="#0e1524" if st.session_state["hunter_theme"] == "dark" else "#ffffff",
                plot_bgcolor="#192538" if st.session_state["hunter_theme"] == "dark" else "#ffffff",
                height=430,
                margin=dict(
                    l=10, r=10,
                    t=20, b=10,
                ),
                xaxis_rangeslider_visible=False,
                legend=dict(
                    orientation="h",
                ),
            )

            st.plotly_chart(
                fig,
                width="stretch",
                theme=None,
                config={
                    "displayModeBar": False,
                    "responsive": True,
                },
            )


# ============================================================
# CANDLE / FAST LAUNCH STUDY
# ============================================================

with tab_candles:
    st.divider()
    st.subheader(tr("candles"))

    launch_cols = st.columns(
        3,
        gap="small",
    )

    with launch_cols[0]:
        st.metric(
            tr("launch_signal"),
            display_signal(launch_signal),
        )

    with launch_cols[1]:
        st.metric(
            tr("strength"),
            f"{launch_strength}/100",
        )

    with launch_cols[2]:
        st.metric(
            tr("direction"),
            f"{launch_score:,.1f}",
        )

    candle_rows = []

    for tf in ["1m", "3m", "5m", "15m"]:
        detail = launch_engine["details"][tf]

        candle = detail["candle"]
        structure = detail["structure"]
        volume = detail["volume"]
        momentum = detail["momentum"]

        volume_ratio_text = (
            "N/A"
            if pd.isna(volume["ratio"])
            else f"{volume['ratio']:.2f}x"
        )

        candle_rows.append({
            tr("timeframe"): tf,
            tr("candle_pattern"): candle["pattern"],
            tr("structure"): structure["structure"],
            tr("volume_state"): volume["state"],
            tr("volume_ratio"): volume_ratio_text,
            tr("momentum_state"): momentum["state"],
            tr("strength_score"): detail["score"],
        })

    hunter_dataframe(
        pd.DataFrame(candle_rows),
        width="stretch",
        hide_index=True,
        height=250,
    )

    st.caption(
        tr("launch_note")
    )

    # Focused candle explanation follows the selected candle timeframe.
    focus_detail = analyze_launch_frame(timeframes[candle_focus_timeframe])

    if AR:
        st.write(
            f"**شمعة {candle_focus_timeframe} الحالية:** "
            f"{focus_detail['candle']['pattern']}"
        )

        st.write(
            f"**الهيكل:** "
            f"{focus_detail['structure']['structure']}"
        )

        st.write(
            f"**الزخم:** "
            f"{focus_detail['momentum']['state']}"
        )

        vol = focus_detail["volume"]

        if not pd.isna(vol["ratio"]):
            st.write(
                f"**الحجم مقارنة بالمتوسط:** "
                f"{vol['ratio']:.2f}x"
            )

    else:
        st.write(
            f"**Current {candle_focus_timeframe} candle:** "
            f"{focus_detail['candle']['pattern']}"
        )

        st.write(
            f"**Structure:** "
            f"{focus_detail['structure']['structure']}"
        )

        st.write(
            f"**Momentum:** "
            f"{focus_detail['momentum']['state']}"
        )

        vol = focus_detail["volume"]

        if not pd.isna(vol["ratio"]):
            st.write(
                f"**Volume vs median:** "
                f"{vol['ratio']:.2f}x"
            )


# ============================================================
# NEWS
# ============================================================

with tab_news:
    st.divider()
    st.subheader(tr("news"))

    news_metrics = st.columns(
        3,
        gap="small",
    )

    if AR:
        news_risk_display = {
            "HIGH": "مرتفع",
            "MEDIUM": "متوسط",
            "LOW": "منخفض",
        }.get(news_state["risk"], news_state["risk"])

        news_bias_display = {
            "BULLISH": "إيجابي",
            "BEARISH": "سلبي",
            "NEUTRAL": "محايد",
        }.get(
            news_state["headline_bias"],
            news_state["headline_bias"]
        )
    else:
        news_risk_display = news_state["risk"]
        news_bias_display = news_state["headline_bias"]

    with news_metrics[0]:
        st.metric(
            tr("news_risk"),
            news_risk_display,
        )

    with news_metrics[1]:
        st.metric(
            tr("headline_bias"),
            news_bias_display,
        )

    with news_metrics[2]:
        st.metric(
            tr("important_news"),
            str(news_state["count"]),
        )

    st.caption(
        tr("news_note")
    )

    if combined_news:
        shown = 0

        for item in combined_news:
            if shown >= 10:
                break

            published = item["published"]

            if published is not None:
                published_text = published.strftime(
                    "%Y-%m-%d %H:%M ET"
                )
            else:
                published_text = "—"

            if AR:
                impact_text = {
                    "HIGH": "مرتفع",
                    "MEDIUM": "متوسط",
                    "LOW": "منخفض",
                }.get(item["impact"], item["impact"])

                bias_text = {
                    "BULLISH": "إيجابي",
                    "BEARISH": "سلبي",
                    "NEUTRAL": "محايد",
                }.get(
                    item["headline_bias"],
                    item["headline_bias"]
                )

                scope_text = (
                    "السوق"
                    if item["scope"] == "MARKET"
                    else symbol
                )
            else:
                impact_text = item["impact"]
                bias_text = item["headline_bias"]
                scope_text = item["scope"]

            if AR:
                display_title = arabic_news_brief(
                    item,
                    max_chars=170,
                )
                summary_text = ""
            else:
                display_title = item["title"]
                summary_text = (
                    item["summary"][:360]
                    if item["summary"]
                    else ""
                )

            summary_html = (
                f'<div class="qt-news-summary">{html.escape(summary_text)}</div>'
                if summary_text
                else ""
            )

            render_html(
                f"""
                <div class="qt-news-card">
                  <div class="qt-news-title">• {html.escape(display_title)}</div>
                  <div class="qt-news-badges">
                    {html.escape(tr("impact"))}: {html.escape(str(impact_text))} •
                    {html.escape(tr("headline_bias"))}: {html.escape(str(bias_text))} •
                    {html.escape(tr("scope"))}: {html.escape(str(scope_text))} •
                    {html.escape(tr("published"))}: {html.escape(published_text)}
                  </div>
                  {summary_html}
                </div>
                """
            )

            if item["link"]:
                st.link_button(
                    (
                        "فتح الخبر"
                        if AR
                        else "Open article"
                    ),
                    item["link"],
                    width="stretch",
                )

            shown += 1

    else:
        st.info(
            tr("news_none")
        )


# ============================================================
# ALL TIMEFRAMES
# ============================================================

with tab_frames:
    st.divider()
    st.subheader(tr("frames"))

    frame_rows = []

    for tf in FRAME_WEIGHTS:
        result = results[tf]

        frame_rows.append({
            tr("timeframe"): tf,
            tr("signal"): display_signal(result["signal"]),
            tr("strength_score"): result["score"],
            "RSI": round(result["rsi"], 1),
            **({tr("weight"): FRAME_WEIGHTS[tf]} if IS_ADMIN else {}),
        })

    hunter_dataframe(
        pd.DataFrame(frame_rows),
        width="stretch",
        hide_index=True,
        height=430,
    )


# ============================================================
# PAPER LOG
# ============================================================

with tab_log:
    st.divider()
    st.subheader(tr("paper_log"))

    init_paper_log()

    open_trade = st.session_state.paper_open_trades.get(
        paper_scope
    )

    if open_trade is None:
        st.info(
            tr("no_open_trade").format(symbol=symbol)
        )
    else:
        pcols = st.columns(
            4,
            gap="small",
        )

        with pcols[0]:
            st.metric(
                tr("open"),
                open_trade["Direction"],
            )

        with pcols[1]:
            st.metric(
                tr("entry"),
                f"{open_trade['Entry Price']:,.2f}",
            )

        with pcols[2]:
            st.metric(
                tr("current"),
                f"{current_price:,.2f}",
            )

        with pcols[3]:
            st.metric(
                tr("status"),
                open_trade["Result"] or tr("running"),
            )

    log_rows = st.session_state.paper_trade_log

    if log_rows:
        log_df = pd.DataFrame(log_rows)

        display_cols = [
            "Symbol",
            "Direction",
            "Entry Time",
            "Entry Price",
            "T1",
            "T2",
            "T3",
            "Invalidation",
            "Status",
            "Result",
            "Exit Time",
            "Exit Price",
        ]

        display_log_df = log_df[display_cols].copy()

        if AR:
            display_log_df = display_log_df.rename(
                columns={
                    "Symbol": "الرمز",
                    "Direction": "الاتجاه",
                    "Entry Time": "وقت الدخول",
                    "Entry Price": "سعر الدخول",
                    "Invalidation": "إلغاء الإشارة",
                    "Status": "الحالة",
                    "Result": "النتيجة",
                    "Exit Time": "وقت الخروج",
                    "Exit Price": "سعر الخروج",
                }
            )

        hunter_dataframe(
            display_log_df,
            width="stretch",
            hide_index=True,
            height=330,
        )

        csv_data = log_df.to_csv(
            index=False
        ).encode("utf-8")

        if IS_ADMIN:
            hunter_require_admin()
            st.download_button(
                tr("download_log"), data=csv_data,
                file_name="hunter_paper_log.csv", mime="text/csv",
                width="stretch",
            )

    else:
        st.caption(
            tr("log_wait")
        )

    st.caption(
        tr("log_session")
    )


# ============================================================
# TEST PANEL
# ============================================================

if IS_ADMIN:
    hunter_require_admin()
    with tab_test:

        test_cols = st.columns(
            5,
            gap="small",
        )

        with test_cols[0]:
            st.metric(
                tr("direction"),
                f"{direction_score:,.1f}",
            )

        with test_cols[1]:
            st.metric(
                tr("previous"),
                f"{previous_direction_score:,.1f}",
            )

        with test_cols[2]:
            st.metric(
                tr("data_age"),
                f"{data_age_minutes:,.1f}m",
            )

        with test_cols[3]:
            st.metric(
                f"ATR {target_timeframe}",
                f"{current_atr:,.2f}",
            )

        with test_cols[4]:
            st.metric(
                tr("wave"),
                display_wave(wave_stage),
            )

        st.write(
            f"**{tr('ny_time')}:** "
            f"{now_ny.strftime('%Y-%m-%d %H:%M:%S ET')}"
        )

        st.write(
            f"**{tr('last_market_data')}:** "
            f"{last_ts_ny.strftime('%Y-%m-%d %H:%M:%S ET')}"
        )

        st.write(
            f"**{tr('action_engine')}:** "
            f"{display_action(action_text)}"
        )

        st.write(
            f"**{tr('launch_signal')}:** "
            f"{display_signal(launch_signal)} "
            f"{launch_strength}/100 "
            f"({launch_score:,.1f})"
        )

        st.write(
            f"**{tr('session_signal_age')}:** "
            f"{signal_age_minutes:,.1f} minutes"
        )

        st.write(
            f"**{tr('distance_entry')}:** "
            f"{entry_distance:,.2f}"
        )

        st.write(
            f"**{tr('distance_zero')}:** "
            f"{zero_distance:,.2f}"
        )

        st.write(
            f"**{tr('target_timeframe')}:** "
            f"{target_timeframe}"
        )

        st.write(
            f"**{tr('chart_tf_global')}:** "
            f"{chart_timeframe}"
        )

        st.write(
            f"**{tr('candle_focus_tf')}:** "
            f"{candle_focus_timeframe}"
        )

        st.write(
            f"**{tr('refresh_every')}:** "
            f"{tr('every_60s')}"
        )

        st.write(
            f"**{tr('higher_tf_context')}:** "
            f"{display_signal(higher_tf_context)}"
        )

        st.write(
            f"**{tr('news_risk')}:** "
            f"{news_state['risk']}"
        )

        st.write(
            f"**{tr('headline_bias')}:** "
            f"{news_state['headline_bias']}"
        )

        st.caption(
            tr("test_note")
        )


# ============================================================
# DISCLAIMER
# ============================================================

disclaimer_text = (
    """
    <b>واجهة تجريبية للتداول الورقي والبحث فقط.</b>
    مخصصة للتعلّم والاختبار ودراسة هيكل السوق. لا تنفذ صفقات حقيقية
    ولا تمثل توصية أو استشارة استثمارية أو مالية أو قانونية أو ضريبية.
    قد تتأخر البيانات أو تنقطع، وقد تخطئ الإشارات والتصنيفات، ولا يوجد
    ضمان لأي هدف سعري أو نتيجة مستقبلية. تستخدم للتجربة الورقية فقط.
    """
    if AR
    else
    """
    <b>Experimental paper-trading research interface.</b>
    For learning, testing and market-structure research only.
    It does not execute trades and does not constitute investment,
    financial, legal or tax advice. Data can be delayed or unavailable,
    model classifications can be wrong, and no price target or future
    result is guaranteed. Use only for simulated/paper testing.
    """
)

st.markdown(
    f"""
    <div class="qt-disclaimer">
    {disclaimer_text}
    </div>
    """,
    unsafe_allow_html=True,
)
