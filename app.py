"""
Performance Timing — Backend Service
Avatar Training

Two endpoints:
  POST /api/subscribe        — intake form writes to MailerLite (existing)
  POST /api/stripe-webhook   — fires ONLY on confirmed Stripe payment;
                                generates and emails the report

SECURITY: the webhook verifies Stripe's signature before doing anything.
An unsigned or forged request is rejected outright — this is what
guarantees "no payment, no report," not just careful coding elsewhere.

Required environment variables (Render dashboard, never in code):
  MAILERLITE_API_KEY     — MailerLite: Integrations -> API
  STRIPE_WEBHOOK_SECRET   — shown once when the webhook endpoint is created
                            in the Stripe Dashboard (Developers -> Webhooks)
  GMAIL_ADDRESS            — the Gmail account reports are sent from
  GMAIL_APP_PASSWORD       — an App Password (not the normal password) —
                            generate at myaccount.google.com/apppasswords
                            (requires 2-Step Verification turned on first)
  NOTIFY_EMAIL             — where failure alerts go (Robert's own inbox)
  TEST_KEY                 — secret string guarding /api/test-report
"""

import os
import re
import json
import smtplib
import tempfile
import threading
import traceback
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

MAILERLITE_GROUP_ID = "195545324381538237"  # Performance Timing Subscribers
DOB_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Stripe retries a webhook if it doesn't get a fast 200 — and it can also
# deliver the same event more than once by design. Without this guard a
# retry would send the subscriber a second identical report. In-memory
# only: a restart clears it, which is acceptable because Stripe's retry
# window is short and a restart mid-retry is rare. Capped so a long-lived
# process can't grow this set indefinitely.
_processed_events = set()
_processed_lock = threading.Lock()


def already_processed(event_id):
    """True if this event id has been seen before. Records it if not."""
    if not event_id:
        return False
    with _processed_lock:
        if event_id in _processed_events:
            return True
        if len(_processed_events) > 5000:
            _processed_events.clear()
        _processed_events.add(event_id)
        return False


def fmt_long(iso_date):
    """2026-09-15 -> 15 September 2026. Display only — never used for logic."""
    return datetime.strptime(iso_date, "%Y-%m-%d").strftime("%d %B %Y").lstrip("0")


def fmt_short(iso_date):
    """2026-09-15 -> 15-09-2026. For dense table rows."""
    return datetime.strptime(iso_date, "%Y-%m-%d").strftime("%d-%m-%Y")


def cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "https://avtrlife.com"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.route("/api/subscribe", methods=["POST", "OPTIONS"])
def subscribe():
    if request.method == "OPTIONS":
        return cors_headers(app.make_default_options_response())

    data = request.get_json(silent=True) or {}
    name = data.get("name")
    email = data.get("email")
    dob = data.get("date_of_birth")

    if not name or not email or not dob:
        return cors_headers(jsonify({"error": "Missing name, email, or date_of_birth"})), 400
    if not DOB_PATTERN.match(dob):
        return cors_headers(jsonify({"error": "date_of_birth must be YYYY-MM-DD"})), 400

    api_key = os.environ.get("MAILERLITE_API_KEY")
    if not api_key:
        return cors_headers(jsonify({"error": "Server not configured (missing MailerLite key)"})), 500

    ml_response = requests.post(
        "https://connect.mailerlite.com/api/subscribers",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        json={"email": email, "fields": {"name": name, "date_of_birth": dob}, "groups": [MAILERLITE_GROUP_ID]},
        timeout=10,
    )
    if not ml_response.ok:
        return cors_headers(jsonify({"error": "MailerLite write failed", "detail": ml_response.text})), 502

    return cors_headers(jsonify({"success": True}))


def verify_stripe_signature(payload, sig_header, secret):
    """Manual Stripe signature check (avoids needing the full `stripe` SDK).
    Rejects anything not genuinely signed by Stripe with this webhook's
    secret — this is the actual mechanism enforcing payment-before-report."""
    import hmac
    import hashlib

    if not sig_header:
        return False
    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    timestamp = parts.get("t")
    signature = parts.get("v1")
    if not timestamp or not signature:
        return False

    signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
    expected = hmac.new(secret.encode("utf-8"), signed_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def get_dob_from_mailerlite(email, api_key):
    resp = requests.get(
        f"https://connect.mailerlite.com/api/subscribers/{email}",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=10,
    )
    if not resp.ok:
        return None
    data = resp.json().get("data", {})
    return data.get("fields", {}).get("date_of_birth")


def notify_failure(reason, detail):
    address = os.environ.get("GMAIL_ADDRESS")
    app_password = os.environ.get("GMAIL_APP_PASSWORD")
    notify_to = os.environ.get("NOTIFY_EMAIL")
    if not (address and app_password and notify_to):
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = f"Performance Timing — action needed: {reason}"
        msg["From"] = address
        msg["To"] = notify_to
        msg.set_content(f"{reason}\n\n{detail}")
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
            smtp.login(address, app_password)
            smtp.send_message(msg)
    except Exception:
        pass  # this IS the failure path — nowhere further to escalate to


def send_report_email(to_email, subscriber_name, pdf_path, ics_path, period_label, peak_date, standdown_count):
    address = os.environ.get("GMAIL_ADDRESS")
    app_password = os.environ.get("GMAIL_APP_PASSWORD")
    first_name = (subscriber_name or "").split(" ")[0] or "there"

    peak_dt = datetime.strptime(peak_date, "%Y-%m-%d")
    peak_display = peak_dt.strftime("%A, %d %B")

    msg = EmailMessage()
    msg["Subject"] = f"Your Performance Timing Calendar — {period_label}"
    msg["From"] = address
    msg["To"] = to_email

    # Plain-text fallback (some clients block HTML, or the person reads on
    # something that strips it) — real content, not just "see attached."
    plain = (
        f"Hi {first_name},\n\n"
        f"Your Performance Timing calendar for {period_label} is ready.\n\n"
        f"Two files are attached:\n"
        f"- A PDF you can save, print, or screenshot — includes your full "
        f"day-by-day breakdown across all five categories.\n"
        f"- A calendar file (.ics) — open it on your phone or computer and "
        f"it adds every day's reading straight into your calendar app.\n\n"
        f"Your Peak Decision Day this cycle is {peak_display} — if you have "
        f"a choice about timing something important, that's the day to use.\n\n"
        f"You also have {standdown_count} Rest & Recovery days flagged this "
        f"cycle, listed on the Month at a Glance page of the PDF.\n\n"
        f"Questions? Just reply to this email.\n\n"
        f"Avatar Training\nL.I.T.A. — Love Is The Answer"
    )
    msg.set_content(plain)

    html = f"""\
<html><body style="margin:0;padding:0;background-color:#0A0A08;font-family:Georgia,'Times New Roman',serif;">
<div style="max-width:520px;margin:0 auto;padding:40px 24px;">
  <p style="font-family:Courier,monospace;font-size:11px;letter-spacing:3px;color:#C9A84C;text-align:center;margin:0 0 24px;">AVATAR TRAINING</p>
  <h1 style="font-size:28px;font-weight:normal;color:#F5F2E8;text-align:center;margin:0 0 8px;">Performance Timing</h1>
  <p style="font-style:italic;font-size:14px;color:#C9A84C;text-align:center;margin:0 0 32px;">{period_label}</p>

  <p style="font-size:15px;color:#D8D4C4;line-height:1.7;">Hi {first_name},</p>
  <p style="font-size:15px;color:#D8D4C4;line-height:1.7;">Your calendar for this cycle is ready — two files are attached.</p>

  <div style="background-color:#161614;border:1px solid #2A2A26;padding:20px 22px;margin:24px 0;">
    <p style="font-family:Courier,monospace;font-size:10px;letter-spacing:2px;color:#8A6E30;margin:0 0 6px;">PEAK DECISION DAY</p>
    <p style="font-size:19px;color:#F5F2E8;margin:0 0 8px;">{peak_display}</p>
    <p style="font-size:13.5px;color:#9A9A8E;line-height:1.6;margin:0;">If you have a choice about timing something important this cycle, this is the day to use it.</p>
  </div>

  <p style="font-size:15px;color:#D8D4C4;line-height:1.7;"><strong style="color:#F5F2E8;">The PDF</strong> — save, print, or screenshot it. Includes your full day-by-day breakdown across all five categories, plus a Month at a Glance page listing your {standdown_count} Rest &amp; Recovery days for this cycle.</p>
  <p style="font-size:15px;color:#D8D4C4;line-height:1.7;"><strong style="color:#F5F2E8;">The calendar file (.ics)</strong> — open it on your phone or computer and every day's reading gets added straight into your calendar app.</p>

  <p style="font-size:14px;color:#9A9A8E;line-height:1.7;margin-top:32px;">Questions? Just reply to this email.</p>

  <div style="border-top:1px solid #2A2A26;margin-top:32px;padding-top:20px;text-align:center;">
    <p style="font-family:'Times New Roman',serif;font-style:italic;font-size:14px;color:#8A6E30;margin:0 0 4px;">L.I.T.A.</p>
    <p style="font-family:Courier,monospace;font-size:9px;letter-spacing:1px;color:#9A9A8E;margin:0;">LOVE IS THE ANSWER</p>
  </div>
</div>
</body></html>"""
    msg.add_alternative(html, subtype="html")

    with open(pdf_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                            filename=os.path.basename(pdf_path))
    with open(ics_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="text", subtype="calendar",
                            filename=os.path.basename(ics_path))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
        smtp.login(address, app_password)
        smtp.send_message(msg)


def build_and_send(customer_email, customer_name, dob, start_date, event_type):
    """The slow part — PDF render plus Gmail SMTP. Runs on a background
    thread so the webhook can answer Stripe immediately. Stripe gives up
    waiting after roughly 10 seconds and marks the delivery failed, then
    retries; doing this work inline is what would cause duplicate sends."""
    try:
        result = generate_report(dob, start_date, customer_name)
        period_label = (f"{fmt_long(result['period']['start_date'])} to "
                        f"{fmt_long(result['period']['end_date'])}")
        send_report_email(
            customer_email, customer_name, result["pdf_path"], result["ics_path"],
            period_label, result["peak_decision_day"], len(result["standdown_days"]),
        )
    except Exception:
        notify_failure("Report generation failed",
                       f"{customer_email} ({event_type}):\n{traceback.format_exc()}")


@app.route("/api/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")

    if not webhook_secret:
        notify_failure("Server not configured", "STRIPE_WEBHOOK_SECRET is not set on Render.")
        return jsonify({"error": "not configured"}), 500

    if not verify_stripe_signature(payload, sig_header, webhook_secret):
        return jsonify({"error": "invalid signature"}), 400

    event = json.loads(payload)
    event_type = event.get("type")
    event_id = event.get("id")

    if already_processed(event_id):
        return jsonify({"received": True, "ignored": "duplicate event"}), 200

    # checkout.session.completed = the FIRST payment (initial signup).
    # invoice.paid = fires on EVERY successful invoice, including the very
    # first one — so handling both naively sends month one twice. Stripe
    # distinguishes them with billing_reason: subscription_create is the
    # signup invoice (already covered by checkout.session.completed), and
    # subscription_cycle is a genuine renewal.
    if event_type == "checkout.session.completed":
        obj = event["data"]["object"]
        customer_email = obj.get("customer_details", {}).get("email") or obj.get("customer_email")
        customer_name = obj.get("customer_details", {}).get("name", "")
        paid = obj.get("payment_status") == "paid"
        paid_at_ts = obj.get("created")
    elif event_type == "invoice.paid":
        obj = event["data"]["object"]
        billing_reason = obj.get("billing_reason")
        if billing_reason != "subscription_cycle":
            # subscription_create (first payment), subscription_update,
            # manual, etc. — not a renewal, don't duplicate the report.
            return jsonify({"received": True, "ignored": f"billing_reason={billing_reason}"}), 200
        customer_email = obj.get("customer_email")
        customer_name = obj.get("customer_name", "")
        paid = obj.get("status") == "paid"
        # Use the moment this invoice was actually paid so the report window
        # starts the day after THIS charge, not today's server time — keeps
        # cycles rolling correctly even if the webhook is processed late.
        paid_at_ts = obj.get("status_transitions", {}).get("paid_at") or obj.get("created")
    else:
        return jsonify({"received": True, "ignored": event_type}), 200

    if not paid:
        return jsonify({"received": True, "ignored": "not paid yet"}), 200
    if not customer_email:
        notify_failure("No email on paid event", f"{event_type} paid but had no customer email.")
        return jsonify({"received": True, "error": "no email"}), 200

    api_key = os.environ.get("MAILERLITE_API_KEY")
    dob = get_dob_from_mailerlite(customer_email, api_key)
    if not dob:
        notify_failure(
            "Paid but no DOB on file",
            f"{customer_email} completed payment ({event_type}) but has no date_of_birth in MailerLite. "
            f"Likely used a different email at checkout than on the intake form. "
            f"Follow up manually to collect DOB and generate their report by hand.",
        )
        return jsonify({"received": True, "error": "no dob on file"}), 200

    paid_at = datetime.utcfromtimestamp(paid_at_ts)
    start_date = (paid_at + timedelta(days=1)).date()

    # Hand off and answer Stripe straight away.
    threading.Thread(
        target=build_and_send,
        args=(customer_email, customer_name, dob, start_date, event_type),
        daemon=True,
    ).start()

    return jsonify({"received": True, "queued": True}), 200


def generate_report(dob_str, start_date, subscriber_name=""):
    import sxtwl
    from dateutil.relativedelta import relativedelta

    STEMS = [("Jia","Yang","Wood"),("Yi","Yin","Wood"),("Bing","Yang","Fire"),("Ding","Yin","Fire"),
             ("Wu","Yang","Earth"),("Ji","Yin","Earth"),("Geng","Yang","Metal"),("Xin","Yin","Metal"),
             ("Ren","Yang","Water"),("Gui","Yin","Water")]
    BRANCHES = [("Zi","Rat","Water"),("Chou","Ox","Earth"),("Yin","Tiger","Wood"),("Mao","Rabbit","Wood"),
                ("Chen","Dragon","Earth"),("Si","Snake","Fire"),("Wu","Horse","Fire"),("Wei","Goat","Earth"),
                ("Shen","Monkey","Metal"),("You","Rooster","Metal"),("Xu","Dog","Earth"),("Hai","Pig","Water")]
    DAY_OFFICERS = ["Establish","Remove","Full","Balance","Stable","Initiate","Destruction","Danger",
                     "Success","Receive","Open","Closed"]
    CLASH_PAIRS = {0:6,6:0,1:7,7:1,2:8,8:2,3:9,9:3,4:10,10:4,5:11,11:5}
    COMBO_PAIRS = {0:1,1:0,2:11,11:2,3:10,10:3,4:9,9:4,5:8,8:5,6:7,7:6}
    GENERATES = {"Wood":"Fire","Fire":"Earth","Earth":"Metal","Metal":"Water","Water":"Wood"}
    CONTROLS = {"Wood":"Earth","Earth":"Water","Water":"Fire","Fire":"Metal","Metal":"Wood"}
    CATEGORIES = ["conversations","commitments","money","launches","rest"]
    BASE_SCORES = {
        "Establish":{"conversations":2,"commitments":1,"money":1,"launches":2,"rest":0},
        "Remove":{"conversations":1,"commitments":0,"money":1,"launches":0,"rest":1},
        "Full":{"conversations":2,"commitments":2,"money":1,"launches":1,"rest":0},
        "Balance":{"conversations":2,"commitments":2,"money":1,"launches":1,"rest":1},
        "Stable":{"conversations":1,"commitments":2,"money":1,"launches":0,"rest":1},
        "Initiate":{"conversations":1,"commitments":1,"money":1,"launches":2,"rest":0},
        "Destruction":{"conversations":0,"commitments":0,"money":0,"launches":0,"rest":2},
        "Danger":{"conversations":0,"commitments":0,"money":0,"launches":0,"rest":2},
        "Success":{"conversations":2,"commitments":2,"money":2,"launches":1,"rest":0},
        "Receive":{"conversations":1,"commitments":1,"money":2,"launches":0,"rest":1},
        "Open":{"conversations":1,"commitments":1,"money":1,"launches":2,"rest":0},
        "Closed":{"conversations":0,"commitments":0,"money":1,"launches":0,"rest":2},
    }

    def ten_god(dm_idx, o_idx):
        dm_el, dm_pol = STEMS[dm_idx][2], STEMS[dm_idx][1]
        o_el, o_pol = STEMS[o_idx][2], STEMS[o_idx][1]
        same = dm_pol == o_pol
        if o_el == dm_el: return "Friend" if same else "Rival"
        if GENERATES[dm_el] == o_el: return "Expression" if same else "Output"
        if CONTROLS[dm_el] == o_el: return "Indirect Wealth" if same else "Direct Wealth"
        if CONTROLS[o_el] == dm_el: return "Challenge" if same else "Authority"
        if GENERATES[o_el] == dm_el: return "Indirect Support" if same else "Direct Support"
        return "Unknown"

    def day_pillar_officer(dt):
        d = sxtwl.fromSolar(dt.year, dt.month, dt.day)
        d_gz, m_gz = d.getDayGZ(), d.getMonthGZ()
        return d_gz.tg, d_gz.dz, (d_gz.dz - m_gz.dz) % 12

    y, m, d = [int(x) for x in dob_str.split("-")]
    natal_day = sxtwl.fromSolar(y, m, d).getDayGZ()
    natal_stem_idx, natal_branch_idx = natal_day.tg, natal_day.dz

    end_date = start_date + relativedelta(months=1) - timedelta(days=1)
    daily = []
    dt = datetime(start_date.year, start_date.month, start_date.day)
    end_dt = datetime(end_date.year, end_date.month, end_date.day)
    while dt <= end_dt:
        stem_idx, branch_idx, officer_idx = day_pillar_officer(dt)
        officer = DAY_OFFICERS[officer_idx]
        base = BASE_SCORES[officer]
        cats = {}
        for cat in CATEGORIES:
            score = base[cat]
            if CLASH_PAIRS.get(branch_idx) == natal_branch_idx:
                score = min(2, score+1) if cat == "rest" else max(0, score-1)
            if COMBO_PAIRS.get(branch_idx) == natal_branch_idx and cat in ("conversations","commitments","money","launches") and score >= 1:
                score = min(2, score+1)
            if cat == "money":
                tg = ten_god(natal_stem_idx, stem_idx)
                if tg in ("Direct Wealth","Indirect Wealth"):
                    score = min(2, score+1)
            cats[cat] = {"score": score, "verdict": {2:"favorable",1:"neutral",0:"avoid"}[score]}
        daily.append({"date": dt.date().isoformat(), "weekday": dt.strftime("%A"), "categories": cats})
        dt += timedelta(days=1)

    def peak_key(day):
        c = day["categories"]
        return sum(x["score"] for x in c.values()) + c["money"]["score"] + c["commitments"]["score"]
    candidates = [x for x in daily if x["categories"]["rest"]["verdict"] != "favorable"]
    peak_day = max(candidates, key=peak_key) if candidates else max(daily, key=peak_key)
    standdown_days = [x["date"] for x in daily if x["categories"]["rest"]["verdict"] == "favorable"]

    data = {
        "subscriber": {"name": subscriber_name, "date_of_birth": dob_str},
        "period": {"start_date": start_date.isoformat(), "end_date": end_date.isoformat()},
        "daily": daily,
        "peak_decision_day": peak_day["date"],
        "standdown_days": standdown_days,
    }

    tmpdir = tempfile.mkdtemp()
    pdf_path = os.path.join(tmpdir, f"PerformanceTiming-{start_date.isoformat()}.pdf")
    ics_path = os.path.join(tmpdir, f"PerformanceTiming-{start_date.isoformat()}.ics")

    render_simple_pdf(data, pdf_path)
    render_ics(data, ics_path)

    return {
        "period": data["period"], "pdf_path": pdf_path, "ics_path": ics_path,
        "peak_decision_day": data["peak_decision_day"], "standdown_days": data["standdown_days"],
    }


# =============================================================================
# PDF RENDERER
# Ported from the performance-timing skill's full renderer so the automated
# report and any manually-generated one look identical. Structure: cover,
# "How to Read This" explainer, Month at a Glance, daily grid, closing.
# Brand colours match avtrlife.com exactly (assets/branding.md).
# =============================================================================

CATEGORY_ORDER = ["conversations", "commitments", "money", "launches", "rest"]

CATEGORY_LABELS = {
    "conversations": "Conversations & Meetings",
    "commitments": "Commitments & Contracts",
    "money": "Money Moves",
    "launches": "Starting Something New",
    "rest": "Rest & Recovery",
}

CATEGORY_DESCRIPTIONS = {
    "conversations": "Difficult conversations, first meetings, and negotiations.",
    "commitments": "Signing, agreeing, and formal commitments of any kind.",
    "money": "Financial decisions \u2014 asks, spending, negotiating, investing.",
    "launches": "New projects, habits, or ventures \u2014 the first move on something.",
    "rest": "Whether to push today, or ease off and protect your energy.",
}

CATEGORY_GRID_HEADER = {
    "conversations": ("Conversations", "& Meetings"),
    "commitments": ("Commitments", "& Contracts"),
    "money": ("Money", "Moves"),
    "launches": ("New", "Starts"),
    "rest": ("Rest &", "Recovery"),
}

VERDICT_SHORT = {"favorable": "Favorable", "neutral": "Neutral", "avoid": "Avoid"}

MONTH_NAMES = ["", "January", "February", "March", "April", "May", "June",
               "July", "August", "September", "October", "November", "December"]


def format_period_label(period):
    """Rolling-window range, e.g. '22 Aug \u2013 21 Sep 2026'."""
    start = datetime.strptime(period["start_date"], "%Y-%m-%d")
    end = datetime.strptime(period["end_date"], "%Y-%m-%d")
    if start.year == end.year:
        return (f"{start.day} {MONTH_NAMES[start.month][:3]} \u2013 "
                f"{end.day} {MONTH_NAMES[end.month][:3]} {end.year}")
    return (f"{start.day} {MONTH_NAMES[start.month][:3]} {start.year} \u2013 "
            f"{end.day} {MONTH_NAMES[end.month][:3]} {end.year}")


def render_simple_pdf(data, output_path):
    """Name kept for backwards compatibility with existing call sites.
    No longer 'simple' \u2014 this is the full branded report."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
    for name, filename in [
        ("Display", "CormorantGaramond-Regular.ttf"),
        ("Display-Bold", "CormorantGaramond-Bold.ttf"),
        ("Display-Italic", "CormorantGaramond-Italic.ttf"),
        ("Mono", "SpaceMono-Regular.ttf"),
        ("Mono-Bold", "SpaceMono-Bold.ttf"),
        ("Body", "DMSans-Regular.ttf"),
        ("Body-Bold", "DMSans-Bold.ttf"),
    ]:
        try:
            pdfmetrics.registerFont(TTFont(name, os.path.join(FONT_DIR, filename)))
        except Exception:
            pass

    FALLBACK = {
        "Display": "Times-Roman", "Display-Bold": "Times-Bold",
        "Display-Italic": "Times-Italic", "Mono": "Courier",
        "Mono-Bold": "Courier-Bold", "Body": "Helvetica",
        "Body-Bold": "Helvetica-Bold",
    }
    registered = set(pdfmetrics.getRegisteredFontNames())

    def F(name):
        """Brand font if it registered, otherwise a base-14 equivalent \u2014
        keeps production from crashing if a font file goes missing."""
        return name if name in registered else FALLBACK[name]

    NAVY = HexColor("#0A0A08")
    GOLD = HexColor("#C9A84C")
    CREAM = HexColor("#F5F2E8")
    BODY_TEXT = HexColor("#1A1A1A")
    META_TEXT = HexColor("#3A362E")
    NEUTRAL_MARK = HexColor("#6E6A58")
    HAIRLINE = HexColor("#DDD5C5")

    # Traffic-light verdict colours. Deliberately muted rather than pure
    # signal colours so they sit on cream without shouting. The verdict WORD
    # is always printed alongside the dot — colour reinforces meaning, it
    # never carries it alone, which keeps the grid readable for the ~8% of
    # men with red/green colour deficiency.
    GO = HexColor("#3E7D4F")       # favorable
    CAUTION = HexColor("#D9971E")  # neutral
    STOP = HexColor("#C0392B")     # avoid

    PAGE_W, PAGE_H = A4
    MARGIN = 18 * mm

    period_label = format_period_label(data["period"])
    name = data["subscriber"].get("name") or "Subscriber"

    def verdict_color(v):
        if v == "favorable":
            return GO
        if v == "avoid":
            return STOP
        return CAUTION

    def page_header(section_name):
        c.setFillColor(CREAM)
        c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        top = PAGE_H - MARGIN
        c.setFillColor(GOLD)
        c.setFont(F("Mono"), 8)
        c.drawString(MARGIN, top, "AVATAR TRAINING \u2014 PERFORMANCE TIMING")
        c.drawRightString(PAGE_W - MARGIN, top, section_name.upper())
        c.setStrokeColor(GOLD)
        c.setLineWidth(0.5)
        c.line(MARGIN, top - 3 * mm, PAGE_W - MARGIN, top - 3 * mm)

    def page_footer(page_num):
        fy = MARGIN - 4 * mm
        c.setStrokeColor(GOLD)
        c.setLineWidth(0.5)
        c.line(MARGIN, fy + 5 * mm, PAGE_W - MARGIN, fy + 5 * mm)
        c.setFillColor(META_TEXT)
        c.setFont(F("Mono"), 7.5)
        c.drawString(MARGIN, fy, f"{name} \u00b7 {period_label}")
        c.drawRightString(PAGE_W - MARGIN, fy, f"Page {page_num}")

    c = canvas.Canvas(output_path, pagesize=A4)
    cx = PAGE_W / 2

    # ---------- COVER ----------
    c.setFillColor(NAVY)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    y = PAGE_H - 60 * mm
    c.setFillColor(GOLD)
    c.setFont(F("Mono"), 10)
    c.drawCentredString(cx, y, "A V A T A R   T R A I N I N G")
    y -= 18 * mm
    c.setStrokeColor(GOLD)
    c.setLineWidth(0.75)
    c.line(cx - 20 * mm, y, cx + 20 * mm, y)
    y -= 18 * mm
    c.setFillColor(CREAM)
    c.setFont(F("Display-Bold"), 40)
    c.drawCentredString(cx, y, "Performance Timing")
    y -= 10 * mm
    c.setFillColor(GOLD)
    c.setFont(F("Display-Italic"), 14)
    c.drawCentredString(cx, y, period_label)
    y -= 30 * mm
    c.setFillColor(CREAM)
    c.setFont(F("Display"), 20)
    c.drawCentredString(cx, y, name)
    y -= 10 * mm
    c.setFont(F("Mono"), 8.5)
    c.drawCentredString(cx, y, f"Prepared {datetime.now().strftime('%d %B %Y')}")
    fy = 35 * mm
    c.setStrokeColor(GOLD)
    c.line(MARGIN, fy, PAGE_W - MARGIN, fy)
    c.setFillColor(GOLD)
    c.setFont(F("Mono"), 8)
    c.drawCentredString(cx, fy - 8 * mm,
                        "L . I . T . A .   \u00b7   L O V E   I S   T H E   A N S W E R")
    c.showPage()

    # ---------- HOW TO READ THIS ----------
    page_header("How to Read This")
    y = PAGE_H - MARGIN - 20 * mm
    c.setFillColor(NAVY)
    c.setFont(F("Display-Bold"), 20)
    c.drawString(MARGIN, y, "How to Read This Calendar")
    y -= 10 * mm
    c.setFillColor(META_TEXT)
    c.setFont(F("Display"), 12)
    c.drawString(MARGIN, y,
                 "Every day this month is scored across five areas of decision-making.")
    y -= 18 * mm

    for cat in CATEGORY_ORDER:
        c.setStrokeColor(GOLD)
        c.setLineWidth(0.5)
        c.line(MARGIN, y, MARGIN + 3 * mm, y)
        c.setFillColor(NAVY)
        c.setFont(F("Display-Bold"), 14.5)
        c.drawString(MARGIN + 6 * mm, y - 1 * mm, CATEGORY_LABELS[cat])
        y -= 7 * mm
        c.setFillColor(META_TEXT)
        c.setFont(F("Display-Italic"), 11.5)
        c.drawString(MARGIN + 6 * mm, y, CATEGORY_DESCRIPTIONS[cat])
        y -= 14 * mm

    y -= 4 * mm
    c.setStrokeColor(GOLD)
    c.setLineWidth(0.5)
    c.line(MARGIN, y, PAGE_W - MARGIN, y)
    y -= 11 * mm
    c.setFillColor(NAVY)
    c.setFont(F("Mono-Bold"), 10.5)
    c.drawString(MARGIN, y, "READING THE MARKS")
    y -= 9 * mm

    for color, term, desc in [
        (GO, "Favorable", "Lean into this \u2014 a stronger-than-usual window for this category."),
        (CAUTION, "Neutral", "No particular signal either way \u2014 use ordinary judgement."),
        (STOP, "Avoid", "Not the day to force this \u2014 where possible, hold off or reschedule."),
    ]:
        c.setFillColor(color)
        c.circle(MARGIN + 1.5 * mm, y + 1 * mm, 1.7 * mm, fill=1, stroke=0)
        c.setFillColor(NAVY)
        c.setFont(F("Mono-Bold"), 11.5)
        c.drawString(MARGIN + 7 * mm, y, term)
        c.setFillColor(META_TEXT)
        c.setFont(F("Display-Italic"), 11)
        c.drawString(MARGIN + 34 * mm, y, desc)
        y -= 9 * mm

    page_footer(2)
    c.showPage()

    # ---------- MONTH AT A GLANCE ----------
    page_header("Month at a Glance")
    y = PAGE_H - MARGIN - 20 * mm
    c.setFillColor(NAVY)
    c.setFont(F("Display-Bold"), 20)
    c.drawString(MARGIN, y, "Month at a Glance")
    y -= 14 * mm

    box_h = 28 * mm
    c.setFillColor(GOLD)
    c.rect(MARGIN, y - box_h, PAGE_W - 2 * MARGIN, box_h, fill=1, stroke=0)
    c.setFillColor(NAVY)
    c.setFont(F("Mono-Bold"), 10)
    c.drawString(MARGIN + 8 * mm, y - 8 * mm, "PEAK DECISION DAY")
    c.setFont(F("Display-Bold"), 20)
    peak_dt = datetime.strptime(data["peak_decision_day"], "%Y-%m-%d")
    c.drawString(MARGIN + 8 * mm, y - 18 * mm, peak_dt.strftime("%A, %d %B"))
    c.setFont(F("Display"), 11.5)
    c.drawString(MARGIN + 8 * mm, y - 25 * mm,
                 "If you have a choice about timing this month, this is the day to use it.")
    y -= box_h + 14 * mm

    c.setFillColor(NAVY)
    c.setFont(F("Mono-Bold"), 12.5)
    c.drawString(MARGIN, y, "REST & RECOVERY DAYS")
    y -= 7 * mm
    c.setFillColor(META_TEXT)
    c.setFont(F("Display"), 11.5)
    c.drawString(MARGIN, y,
                 "These are the days this month best suited to protecting your "
                 "capacity rather than pushing it.")
    y -= 11 * mm

    col_width = 55 * mm
    row_h = 8 * mm
    for i, iso_date in enumerate(data["standdown_days"]):
        x = MARGIN + (i % 3) * col_width
        yy = y - (i // 3) * row_h
        dt = datetime.strptime(iso_date, "%Y-%m-%d")
        c.setFillColor(NAVY)
        c.setFont(F("Body"), 11)
        c.drawString(x, yy, "\u2022  " + dt.strftime("%a %d %b"))

    y -= ((len(data["standdown_days"]) + 2) // 3) * row_h + 14 * mm

    # Month summary — how many favorable days fall in each category. Gives
    # the subscriber something to act on at a glance without reading the
    # full grid, and stops this page ending in dead space.
    c.setStrokeColor(GOLD)
    c.setLineWidth(0.5)
    c.line(MARGIN, y, PAGE_W - MARGIN, y)
    y -= 11 * mm
    c.setFillColor(NAVY)
    c.setFont(F("Mono-Bold"), 12.5)
    c.drawString(MARGIN, y, "FAVORABLE DAYS THIS CYCLE")
    y -= 7 * mm
    c.setFillColor(META_TEXT)
    c.setFont(F("Display"), 11.5)
    c.drawString(MARGIN, y,
                 "How many days this cycle carry a strong signal in each area.")
    y -= 12 * mm

    total_days = len(data["daily"])
    for cat in CATEGORY_ORDER:
        count = sum(1 for d in data["daily"]
                    if d["categories"][cat]["verdict"] == "favorable")
        c.setFillColor(NAVY)
        c.setFont(F("Display"), 12.5)
        c.drawString(MARGIN + 6 * mm, y, CATEGORY_LABELS[cat])

        # Proportional bar — quiet, gold, no solid blocks of colour
        bar_x = MARGIN + 78 * mm
        bar_w = 62 * mm
        c.setStrokeColor(HAIRLINE)
        c.setLineWidth(0.5)
        c.line(bar_x, y - 1 * mm, bar_x + bar_w, y - 1 * mm)
        if total_days:
            c.setStrokeColor(GOLD)
            c.setLineWidth(2.2)
            c.line(bar_x, y - 1 * mm,
                   bar_x + bar_w * (count / total_days), y - 1 * mm)

        c.setFillColor(META_TEXT)
        c.setFont(F("Mono-Bold"), 10)
        c.drawRightString(PAGE_W - MARGIN, y, f"{count} of {total_days}")
        y -= 10 * mm

    page_footer(3)
    c.showPage()

    # ---------- DAILY GRID ----------
    daily = data["daily"]
    # Split evenly across two pages rather than filling the first and
    # leaving the second half-empty — a page with dead space at the bottom
    # reads as unfinished.
    rows_per_page = -(-len(daily) // 2)
    row_h = 13 * mm
    page_num = 4
    idx = 0
    date_col_w = 32 * mm
    cat_col_w = (PAGE_W - 2 * MARGIN - date_col_w) / 5

    while idx < len(daily):
        page_header("Monthly Calendar")
        y = PAGE_H - MARGIN - 16 * mm
        c.setFillColor(NAVY)
        c.setFont(F("Display-Bold"), 17)
        c.drawString(MARGIN, y, "Daily Timing")
        y -= 13 * mm

        c.setFillColor(META_TEXT)
        c.setFont(F("Mono-Bold"), 8.5)
        x = MARGIN
        c.drawString(x, y, "DATE")
        x += date_col_w
        for cat in CATEGORY_ORDER:
            line1, line2 = CATEGORY_GRID_HEADER[cat]
            ccx = x + cat_col_w / 2
            c.drawCentredString(ccx, y, line1)
            c.drawCentredString(ccx, y - 3.5 * mm, line2)
            x += cat_col_w
        y -= 9 * mm
        c.setStrokeColor(GOLD)
        c.setLineWidth(0.75)
        c.line(MARGIN, y, PAGE_W - MARGIN, y)
        y -= 11 * mm

        rows_this_page = 0
        while idx < len(daily) and rows_this_page < rows_per_page:
            day = daily[idx]
            dt = datetime.strptime(day["date"], "%Y-%m-%d")
            is_peak = day["date"] == data["peak_decision_day"]

            x = MARGIN
            c.setFillColor(NAVY if is_peak else BODY_TEXT)
            c.setFont(F("Display-Bold") if is_peak else F("Display"), 11.5)
            c.drawString(x, y, dt.strftime("%a %d %b"))
            if is_peak:
                c.setFillColor(GOLD)
                c.setFont(F("Mono-Bold"), 7.5)
                c.drawString(x, y - 4.5 * mm, "PEAK DAY")
            x += date_col_w

            for cat in CATEGORY_ORDER:
                verdict = day["categories"][cat]["verdict"]
                marker = verdict_color(verdict)
                ccx = x + cat_col_w / 2
                label = VERDICT_SHORT[verdict]

                # Marker sits inline, immediately left of the word. Stacking
                # it above the text made it ambiguous which row it belonged
                # to once the rows were tightened.
                c.setFont(F("Mono-Bold"), 9.5)
                text_w = c.stringWidth(label, F("Mono-Bold"), 9.5)
                dot_r = 1.15 * mm
                gap = 1.8 * mm
                block_w = dot_r * 2 + gap + text_w
                block_x = ccx - block_w / 2

                c.setFillColor(marker)
                c.circle(block_x + dot_r, y + 1.1 * mm, dot_r, fill=1, stroke=0)
                c.setFillColor(marker)
                c.drawString(block_x + dot_r * 2 + gap, y, label)
                x += cat_col_w

            y -= row_h
            c.setStrokeColor(HAIRLINE)
            c.setLineWidth(0.4)
            c.line(MARGIN, y + 5 * mm, PAGE_W - MARGIN, y + 5 * mm)
            idx += 1
            rows_this_page += 1

        page_footer(page_num)
        c.showPage()
        page_num += 1

    # ---------- CLOSING ----------
    c.setFillColor(NAVY)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    y = PAGE_H / 2 + 20 * mm
    c.setStrokeColor(GOLD)
    c.setLineWidth(0.75)
    c.line(cx - 20 * mm, y, cx + 20 * mm, y)
    y -= 14 * mm
    c.setFillColor(CREAM)
    c.setFont(F("Display-Bold"), 26)
    c.drawCentredString(cx, y, "L.I.T.A.")
    y -= 8 * mm
    c.setFillColor(GOLD)
    c.setFont(F("Display-Italic"), 12)
    c.drawCentredString(cx, y, "Love Is The Answer")
    y -= 24 * mm
    c.setFillColor(CREAM)
    c.setFont(F("Display"), 10)
    c.drawCentredString(cx, y, "Did you act on your Peak Decision Day this month?")
    y -= 6 * mm
    c.drawCentredString(cx, y, "Reply and let us know \u2014 we'd love to hear how it went.")
    c.setFillColor(GOLD)
    c.setFont(F("Mono"), 9)
    c.drawCentredString(cx, 30 * mm, "avtrlife.com  \u00b7  hello@avtrlife.com")
    c.showPage()

    c.save()


def render_ics(data, output_path):
    import uuid
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Avatar Training//Performance Timing//EN", "CALSCALE:GREGORIAN"]
    for day in data["daily"]:
        d = datetime.strptime(day["date"], "%Y-%m-%d")
        d_end = d + timedelta(days=1)
        favorable = [k for k, v in day["categories"].items() if v["verdict"] == "favorable"]
        title = "Peak Decision Day" if day["date"] == data["peak_decision_day"] else (
            "Favorable: " + ", ".join(favorable) if favorable else "Performance Timing")
        lines += [
            "BEGIN:VEVENT",
            f"UID:{uuid.uuid4()}@avtrlife.com",
            f"DTSTAMP:{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}",
            f"DTSTART;VALUE=DATE:{d.strftime('%Y%m%d')}",
            f"DTEND;VALUE=DATE:{d_end.strftime('%Y%m%d')}",
            f"SUMMARY:{title} \u2014 Performance Timing",
            "END:VEVENT",
        ]
    lines.append("END:VCALENDAR")
    with open(output_path, "w", newline="") as f:
        f.write("\r\n".join(lines) + "\r\n")


@app.route("/api/test-report", methods=["GET"])
def test_report():
    """Manual end-to-end test — no Stripe, no payment.
    Call: /api/test-report?key=TEST_KEY&dob=1985-03-12&email=you@example.com
    Returns the full traceback in the browser if anything fails."""
    if request.args.get("key") != os.environ.get("TEST_KEY"):
        return jsonify({"error": "unauthorized"}), 403

    dob = request.args.get("dob")
    email = request.args.get("email")
    if not dob or not DOB_PATTERN.match(dob):
        return jsonify({"error": "dob missing or not YYYY-MM-DD"}), 400
    if not email:
        return jsonify({"error": "email missing"}), 400

    try:
        start = (datetime.utcnow() + timedelta(days=1)).date()
        result = generate_report(dob, start, request.args.get("name", "Test"))
        label = (f"{fmt_long(result['period']['start_date'])} to "
                 f"{fmt_long(result['period']['end_date'])}")
        send_report_email(
            email, "Test", result["pdf_path"], result["ics_path"], label,
            result["peak_decision_day"], len(result["standdown_days"]),
        )
        return jsonify({"ok": True, "period": label, "sent_to": email})
    except Exception:
        return jsonify({"ok": False, "trace": traceback.format_exc()}), 500


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "performance-timing-backend"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
