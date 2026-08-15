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
import traceback
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

MAILERLITE_GROUP_ID = "195545324381538237"  # Performance Timing Subscribers
DOB_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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

    # checkout.session.completed = the FIRST payment (initial signup).
    # invoice.paid = every RENEWAL payment thereafter (month 2, 3, 4...).
    # Both must be handled, or reports stop after the first month.
    if event_type == "checkout.session.completed":
        obj = event["data"]["object"]
        customer_email = obj.get("customer_details", {}).get("email") or obj.get("customer_email")
        customer_name = obj.get("customer_details", {}).get("name", "")
        paid = obj.get("payment_status") == "paid"
        paid_at_ts = obj.get("created")
    elif event_type == "invoice.paid":
        obj = event["data"]["object"]
        customer_email = obj.get("customer_email")
        customer_name = obj.get("customer_name", "")
        paid = obj.get("status") == "paid"
        # Use the invoice's period start (when this billing cycle began) so
        # the report window starts the day after THIS charge, not today's
        # server time — keeps cycles rolling correctly even if the webhook
        # is processed slightly late.
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

    try:
        result = generate_report(dob, start_date)
        period_label = (f"{fmt_long(result['period']['start_date'])} to "
                        f"{fmt_long(result['period']['end_date'])}")
        send_report_email(
            customer_email, customer_name, result["pdf_path"], result["ics_path"],
            period_label, result["peak_decision_day"], len(result["standdown_days"]),
        )
    except Exception:
        notify_failure("Report generation failed",
                       f"{customer_email} ({event_type}):\n{traceback.format_exc()}")
        return jsonify({"received": True, "error": "generation failed"}), 200

    return jsonify({"received": True, "sent": True}), 200


def generate_report(dob_str, start_date):
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
        "subscriber": {"name": "", "date_of_birth": dob_str},
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


def render_simple_pdf(data, output_path):
    """Uses the real Avatar Training brand fonts (Cormorant Garamond, Space
    Mono, DM Sans), bundled directly in this repo's fonts/ folder as static
    weight instances extracted from Google's variable font files — so
    rendering doesn't depend on what happens to be installed on the server.
    See fonts/README.md for how these were generated if they ever need
    regenerating (e.g. a new weight)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
    for name, filename in [
        ("Cormorant", "CormorantGaramond-Regular.ttf"),
        ("Cormorant-Bold", "CormorantGaramond-Bold.ttf"),
        ("Cormorant-Italic", "CormorantGaramond-Italic.ttf"),
        ("DMSans", "DMSans-Regular.ttf"),
        ("DMSans-Bold", "DMSans-Bold.ttf"),
        ("SpaceMono", "SpaceMono-Regular.ttf"),
        ("SpaceMono-Bold", "SpaceMono-Bold.ttf"),
    ]:
        try:
            pdfmetrics.registerFont(TTFont(name, os.path.join(FONT_DIR, filename)))
        except Exception:
            pass  # falls through to base-14 names below if a font is missing

    def f(brand_name, fallback):
        """Use the brand font if it registered successfully, otherwise the
        reportlab base-14 fallback — keeps this from crashing in production
        even if a font file is ever missing."""
        return brand_name if brand_name in pdfmetrics.getRegisteredFontNames() else fallback

    NAVY, GOLD, CREAM = HexColor("#0A0A08"), HexColor("#C9A84C"), HexColor("#F5F2E8")
    c = canvas.Canvas(output_path, pagesize=A4)
    W, H = A4

    c.setFillColor(NAVY); c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(GOLD); c.setFont(f("SpaceMono", "Helvetica"), 10)
    c.drawCentredString(W/2, H-60*mm, "AVATAR TRAINING")
    c.setFillColor(CREAM); c.setFont(f("Cormorant-Bold", "Times-Bold"), 32)
    c.drawCentredString(W/2, H-80*mm, "Performance Timing")
    c.setFillColor(GOLD); c.setFont(f("Cormorant-Italic", "Times-Italic"), 13)
    c.drawCentredString(W/2, H-90*mm,
                        f"{fmt_long(data['period']['start_date'])} to "
                        f"{fmt_long(data['period']['end_date'])}")
    c.showPage()

    c.setFillColor(CREAM); c.rect(0, 0, W, H, fill=1, stroke=0)
    y = H - 25*mm
    c.setFillColor(NAVY); c.setFont(f("Cormorant-Bold", "Times-Bold"), 18)
    c.drawString(18*mm, y, "Peak Decision Day"); y -= 10*mm
    c.setFont(f("DMSans", "Times-Roman"), 13)
    c.drawString(18*mm, y, fmt_long(data["peak_decision_day"])); y -= 16*mm
    c.setFont(f("Cormorant-Bold", "Times-Bold"), 14)
    c.drawString(18*mm, y, "Rest & Recovery Days"); y -= 8*mm
    c.setFont(f("DMSans", "Times-Roman"), 10)
    for sd in data["standdown_days"]:
        c.drawString(18*mm, y, f"- {fmt_long(sd)}"); y -= 6*mm
        if y < 20*mm:
            c.showPage(); c.setFillColor(CREAM); c.rect(0,0,W,H,fill=1,stroke=0); y = H-25*mm
    c.showPage()

    c.setFillColor(CREAM); c.rect(0, 0, W, H, fill=1, stroke=0)
    y = H - 25*mm
    c.setFillColor(NAVY); c.setFont(f("Cormorant-Bold", "Times-Bold"), 16)
    c.drawString(18*mm, y, "Daily Timing"); y -= 12*mm
    c.setFont(f("SpaceMono", "Helvetica-Bold"), 8)
    for day in data["daily"]:
        if y < 20*mm:
            c.showPage(); c.setFillColor(CREAM); c.rect(0,0,W,H,fill=1,stroke=0); y = H-25*mm
            c.setFillColor(NAVY); c.setFont(f("SpaceMono", "Helvetica-Bold"), 8)
        line = f"{fmt_short(day['date'])} ({day['weekday'][:3]}): " + " | ".join(
            f"{k[:4]}:{v['verdict'][:3]}" for k, v in day["categories"].items()
        )
        c.setFillColor(NAVY)
        c.drawString(18*mm, y, line)
        y -= 6*mm
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
        result = generate_report(dob, start)
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
