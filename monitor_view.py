import math
from html import escape
from urllib.parse import urlencode

import streamlit as st


SYMBOLS = ["SPX", "TSLA", "MSTR", "MU", "CRWD"]

FRAMES = [
    "1m", "3m", "5m", "10m", "15m", "30m", "45m",
    "1H", "2H", "4H", "6H", "8H",
    "Daily", "Weekly", "Monthly",
]

FRAME_NAMES = {
    "Daily": "يومي",
    "Weekly": "أسبوعي",
    "Monthly": "شهري",
}

ACTIVE_STATES = {"LIVE", "PRE-MARKET", "POST-MARKET"}


def monitor_prepare():
    """Apply valid navigation choices before the main app creates widgets."""
    view = st.query_params.get("view", "detail")
    symbol = st.query_params.get("symbol", "")
    frame = st.query_params.get("tf", "")
    route = (view, symbol, frame)

    # Do not overwrite normal widget changes on every automatic refresh.
    if st.session_state.get("_monitor_route") != route:
        if symbol in SYMBOLS:
            st.session_state["hunter_symbol"] = symbol
        if frame in FRAMES:
            st.session_state["hunter_analysis_tf"] = frame
        st.session_state["_monitor_route"] = route


def monitor_requested():
    return st.query_params.get("view") == "monitor"


def monitor_url(symbol, frame, view="monitor"):
    return "?" + urlencode({
        "view": view,
        "symbol": symbol,
        "tf": frame,
    })


def monitor_open_button(symbol, frame):
    url = escape(monitor_url(symbol, frame), quote=True)
    st.markdown(
        f'<a href="{url}" target="_self" '
        'style="display:inline-block;padding:14px 22px;'
        'border-radius:12px;background:#174ea6;color:white;'
        'font-size:20px;font-weight:bold;text-decoration:none">'
        'فتح شاشة المراقبة الكبيرة ↗</a>',
        unsafe_allow_html=True,
    )


def number(value):
    try:
        value = float(value)
        return f"{value:,.2f}" if math.isfinite(value) else "غير متاح"
    except (TypeError, ValueError):
        return "غير متاح"


def price_range(low, high):
    return (
        f'<bdi dir="ltr">{number(low)}</bdi>'
        '<span class="hm-between">إلى</span>'
        f'<bdi dir="ltr">{number(high)}</bdi>'
    )


def card(title, content):
    return (
        '<div class="hm-card">'
        f'<div class="hm-label">{escape(title)}</div>'
        f'<div class="hm-number">{content}</div>'
        '</div>'
    )


def render_monitor(
    *,
    symbol,
    frame,
    price,
    signal,
    strength,
    wave,
    entry_low,
    entry_high,
    watch_low,
    watch_high,
    targets,
    invalidation,
    market_status,
    updated_at,
    data_age,
    action,
):
    """Display the existing engine snapshot. No downloads or new predictions."""
    try:
        age = float(data_age)
        fresh = (
            market_status in ACTIVE_STATES
            and math.isfinite(age)
            and 0 <= age <= 3
        )
    except (TypeError, ValueError):
        age = None
        fresh = False

    directions = {
        "CALL": "كول ↑",
        "PUT": "بوت ↓",
        "WAIT": "انتظار —",
    }
    direction = directions.get(signal, "انتظار —")

    colors = {
        "CALL": "#86efac",
        "PUT": "#fda4af",
        "WAIT": "#fde68a",
    }
    accent = colors.get(signal, "#fde68a") if fresh else "#cbd5e1"

    statuses = {
        "LIVE": "جلسة عادية — بيانات حديثة",
        "PRE-MARKET": "قبل الافتتاح — بيانات حديثة",
        "POST-MARKET": "بعد الإغلاق — بيانات حديثة",
        "CLOSED": "السوق مغلق — آخر قراءة متاحة",
        "WEEKEND": "عطلة أسبوعية — آخر قراءة متاحة",
        "HOLIDAY": "عطلة سوق — آخر قراءة متاحة",
        "STALE": "بيانات متأخرة — لا إشارة دخول حديثة",
        "UNKNOWN": "حالة البيانات غير معروفة",
    }
    status_text = statuses.get(
        market_status, "تحقق من حالة البيانات"
    )
    if not fresh and market_status in ACTIVE_STATES:
        status_text = "بيانات متأخرة — لا إشارة دخول حديثة"

    waves = {
        "START CALL": "بداية موجة كول",
        "START PUT": "بداية موجة بوت",
        "CALL ACTIVE": "موجة كول نشطة",
        "PUT ACTIVE": "موجة بوت نشطة",
        "CALL WEAKENING": "ضعف موجة الكول",
        "PUT WEAKENING": "ضعف موجة البوت",
        "CALL WATCH": "مراقبة كول",
        "PUT WATCH": "مراقبة بوت",
        "ZERO WATCH": "مراقبة مستوى — الانعكاس غير مؤكد",
        "CONFIRMED CALL": "تأكيد المحرك لاتجاه الكول",
        "CONFIRMED PUT": "تأكيد المحرك لاتجاه البوت",
        "WAIT": "انتظار وضوح الاتجاه",
    }

    wave_text = waves.get(wave, str(wave))
    action_text = str(action) if fresh else "انتظار بيانات حديثة"
    direction_text = direction if fresh else f"قراءة سابقة: {direction}"

    try:
        score_value = float(strength)
        score = (
            f"{score_value:.0f}/100"
            if math.isfinite(score_value)
            else "غير متاح"
        )
    except (TypeError, ValueError):
        score = "غير متاح"

    age_text = (
        f"{age:.1f} دقيقة"
        if age is not None and math.isfinite(age)
        else "غير معروف"
    )
    if age is not None and math.isfinite(age) and age >= 60:
        age_text = f"{age / 60:.1f} ساعة"

    symbol_links = "".join(
        f'<a class="{"hm-selected" if item == symbol else ""}" '
        f'href="{escape(monitor_url(item, frame), quote=True)}" '
        f'target="_self">{escape(item)}</a>'
        for item in SYMBOLS
    )
    frame_links = "".join(
        f'<a class="{"hm-selected" if item == frame else ""}" '
        f'href="{escape(monitor_url(symbol, item), quote=True)}" '
        f'target="_self">{escape(FRAME_NAMES.get(item, item))}</a>'
        for item in FRAMES
    )

    levels = (
        card("نطاق الدخول المرجعي", price_range(entry_low, entry_high))
        + card("نطاق المراقبة", price_range(watch_low, watch_high))
        + card(
            "إلغاء السيناريو",
            f'<bdi dir="ltr">{number(invalidation)}</bdi>',
        )
    )

    values = list(targets or [])[:3]
    values += [None] * (3 - len(values))
    target_cards = "".join(
        card(
            f"الهدف {i} · T{i}",
            f'<bdi dir="ltr">{number(value)}</bdi>',
        )
        for i, value in enumerate(values, start=1)
    )

    detail_url = escape(
        monitor_url(symbol, frame, "detail"),
        quote=True,
    )

    css = """
    <style>
    /* Visual presentation only; owner authorization stays in app.py. */
    .stApp .block-container {visibility:hidden;}

    #hunter-monitor, #hunter-monitor * {
        visibility:visible;
        box-sizing:border-box;
    }

    #hunter-monitor {
        position:fixed;
        inset:0;
        z-index:999999;
        overflow:auto;
        background:#07111f;
        color:#f8fafc;
        padding:22px;
        direction:rtl;
        font-family:Tahoma,Arial,sans-serif;
        line-height:1.5;
    }

    #hunter-monitor .hm-wrap {
        max-width:1700px;
        margin:auto;
    }

    #hunter-monitor .hm-nav {
        display:flex;
        flex-wrap:wrap;
        gap:9px;
        margin-bottom:12px;
    }

    #hunter-monitor a {
        color:#f8fafc;
        background:#17263b;
        border:2px solid #64748b;
        border-radius:10px;
        padding:9px 14px;
        font-size:20px;
        font-weight:700;
        text-decoration:none;
    }

    #hunter-monitor a:focus-visible {
        outline:4px solid #facc15;
        outline-offset:3px;
    }

    #hunter-monitor a.hm-selected {
        border-color:#67e8f9;
        background:#164e63;
    }

    #hunter-monitor .hm-status {
        background:#17263b;
        padding:12px;
        border-radius:12px;
        font-size:clamp(20px,2vw,30px);
        font-weight:bold;
    }

    #hunter-monitor .hm-price {
        font-size:clamp(64px,11vw,170px);
        font-weight:900;
        line-height:1.2;
        font-variant-numeric:tabular-nums;
        text-align:center;
        margin:14px 0;
        color:#ffffff;
    }

    #hunter-monitor .hm-direction {
        color:var(--accent);
        text-align:center;
        font-weight:900;
        font-size:clamp(32px,4vw,64px);
    }

    #hunter-monitor .hm-wave {
        text-align:center;
        font-size:clamp(22px,2.4vw,36px);
        margin-bottom:16px;
    }

    #hunter-monitor .hm-grid {
        display:grid;
        grid-template-columns:repeat(3,minmax(0,1fr));
        gap:14px;
        margin:14px 0;
    }

    #hunter-monitor .hm-card {
        background:#142238;
        border:2px solid #64748b;
        border-radius:16px;
        padding:18px;
        text-align:center;
    }

    #hunter-monitor .hm-label {
        color:#e2e8f0;
        font-size:clamp(20px,2vw,28px);
        font-weight:700;
    }

    #hunter-monitor .hm-number {
        color:#ffffff;
        font-size:clamp(28px,3.4vw,54px);
        font-weight:900;
        font-variant-numeric:tabular-nums;
        overflow-wrap:anywhere;
    }

    #hunter-monitor .hm-between {
        display:block;
        font-size:20px;
        color:#cbd5e1;
    }

    #hunter-monitor .hm-note {
        color:#cbd5e1;
        font-size:18px;
        margin-top:12px;
    }

    @media(max-width:700px) {
        #hunter-monitor {padding:12px;}
        #hunter-monitor .hm-grid {grid-template-columns:1fr;}
        #hunter-monitor a {font-size:18px;}
        #hunter-monitor .hm-price {font-size:clamp(52px,12vw,90px);}
    }
    </style>
    """

    markup = (
        f'<section id="hunter-monitor" aria-label="شاشة مراقبة السوق" '
        f'style="--accent:{accent}"><div class="hm-wrap">'
        f'<nav class="hm-nav" aria-label="اختيار السهم">{symbol_links}</nav>'
        f'<nav class="hm-nav" aria-label="اختيار الفريم">{frame_links}</nav>'
        f'<div class="hm-status">{escape(symbol)} · '
        f'{escape(FRAME_NAMES.get(frame, frame))} · '
        f'{escape(status_text)}</div>'
        f'<div class="hm-price"><bdi dir="ltr">{number(price)}</bdi></div>'
        f'<div class="hm-direction">{escape(direction_text)}</div>'
        f'<div class="hm-wave">{escape(wave_text)} · '
        f'درجة المؤشرات {escape(score)}</div>'
        f'<div class="hm-status">{escape(action_text)}</div>'
        f'<div class="hm-grid">{levels}</div>'
        f'<div class="hm-grid">{target_cards}</div>'
        f'<div class="hm-note">آخر بيانات السعر: '
        f'<bdi dir="ltr">{escape(str(updated_at))}</bdi>'
        f' · عمر البيانات: {escape(age_text)}</div>'
        '<div class="hm-note">المستويات متجددة مع حسابات المحرك. '
        'نطاق المراقبة لا يثبت حدوث انعكاس. درجة المؤشرات ليست احتمال نجاح، '
        'والأهداف ليست مضمونة.</div>'
        '<div class="hm-note">تحديث دوري حسب مصدر الأسعار؛ '
        'ليس بث صفقات لحظيًا مضمونًا. لتكبير العرض على الكمبيوتر اضغط F11.</div>'
        f'<nav class="hm-nav" style="margin-top:18px">'
        f'<a href="{detail_url}" target="_self">العودة للصفحة التفصيلية</a>'
        '</nav></div></section>'
    )

    st.markdown(css + markup, unsafe_allow_html=True)
