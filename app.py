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
"""

import os
import re
import json
import smtplib
import tempfile
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

MAILERLITE_GROUP_ID = "195545324381538237"  # Performance Timing Subscribers
DOB_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(address, app_password)
            smtp.send_message(msg)
    except Exception:
        pass  # this IS the failure path — nowhere further to escalate to


def send_report_email(to_email, subscriber_name, pdf_path, ics_path, period_label):
    address = os.environ.get("GMAIL_ADDRESS")
    app_password = os.environ.get("GMAIL_APP_PASSWORD")

    msg = EmailMessage()
    msg["Subject"] = f"Your Performance Timing Calendar — {period_label}"
    msg["From"] = address
    msg["To"] = to_email
    msg.set_content(
        f"Hi {subscriber_name or 'there'},\n\n"
        f"Your Performance Timing calendar for {period_label} is attached — "
        f"a PDF you can save or print, and a calendar file that syncs "
        f"straight into your phone.\n\n"
        f"Avatar Training\nL.I.T.A."
    )
    with open(pdf_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                            filename=os.path.basename(pdf_path))
    with open(ics_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="text", subtype="calendar",
                            filename=os.path.basename(ics_path))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
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

    if event_type != "checkout.session.completed":
        return jsonify({"received": True, "ignored": event_type}), 200

    session = event["data"]["object"]
    customer_email = session.get("customer_details", {}).get("email") or session.get("customer_email")
    payment_status = session.get("payment_status")

    if payment_status != "paid":
        return jsonify({"received": True, "ignored": "not paid yet"}), 200
    if not customer_email:
        notify_failure("No email on paid session", f"Session {session.get('id')} paid but had no customer email.")
        return jsonify({"received": True, "error": "no email"}), 200

    api_key = os.environ.get("MAILERLITE_API_KEY")
    dob = get_dob_from_mailerlite(customer_email, api_key)
    if not dob:
        notify_failure(
            "Paid but no DOB on file",
            f"{customer_email} completed payment but has no date_of_birth in MailerLite. "
            f"Likely used a different email at checkout than on the intake form. "
            f"Follow up manually to collect DOB and generate their report by hand.",
        )
        return jsonify({"received": True, "error": "no dob on file"}), 200

    paid_at = datetime.utcfromtimestamp(session["created"])
    start_date = (paid_at + timedelta(days=1)).date()

    try:
        result = generate_report(dob, start_date)
        period_label = f"{result['period']['start_date']} to {result['period']['end_date']}"
        subscriber_name = session.get("customer_details", {}).get("name", "")
        send_report_email(customer_email, subscriber_name, result["pdf_path"], result["ics_path"], period_label)
    except Exception as e:
        notify_failure("Report generation failed", f"{customer_email}: {repr(e)}")
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

    return {"period": data["period"], "pdf_path": pdf_path, "ics_path": ics_path}


def render_simple_pdf(data, output_path):
    """Simplified renderer for the automated pipeline — base-14 fonts only,
    no TTF dependency, so it can't fail on a server without the brand fonts
    installed. Full brand-matched rendering stays the tool for reports
    Robert generates and reviews himself; this is the guaranteed-to-run
    version for unattended delivery."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor

    NAVY, GOLD, CREAM = HexColor("#0A0A08"), HexColor("#C9A84C"), HexColor("#F5F2E8")
    c = canvas.Canvas(output_path, pagesize=A4)
    W, H = A4

    c.setFillColor(NAVY); c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(GOLD); c.setFont("Helvetica", 10)
    c.drawCentredString(W/2, H-60*mm, "AVATAR TRAINING")
    c.setFillColor(CREAM); c.setFont("Times-Bold", 32)
    c.drawCentredString(W/2, H-80*mm, "Performance Timing")
    c.setFillColor(GOLD); c.setFont("Times-Italic", 13)
    c.drawCentredString(W/2, H-90*mm, f"{data['period']['start_date']} to {data['period']['end_date']}")
    c.showPage()

    c.setFillColor(CREAM); c.rect(0, 0, W, H, fill=1, stroke=0)
    y = H - 25*mm
    c.setFillColor(NAVY); c.setFont("Times-Bold", 18)
    c.drawString(18*mm, y, "Peak Decision Day"); y -= 10*mm
    c.setFont("Times-Roman", 13)
    c.drawString(18*mm, y, data["peak_decision_day"]); y -= 16*mm
    c.setFont("Times-Bold", 14)
    c.drawString(18*mm, y, "Rest & Recovery Days"); y -= 8*mm
    c.setFont("Times-Roman", 10)
    for sd in data["standdown_days"]:
        c.drawString(18*mm, y, f"- {sd}"); y -= 6*mm
        if y < 20*mm:
            c.showPage(); c.setFillColor(CREAM); c.rect(0,0,W,H,fill=1,stroke=0); y = H-25*mm
    c.showPage()

    c.setFillColor(CREAM); c.rect(0, 0, W, H, fill=1, stroke=0)
    y = H - 25*mm
    c.setFillColor(NAVY); c.setFont("Times-Bold", 16)
    c.drawString(18*mm, y, "Daily Timing"); y -= 12*mm
    c.setFont("Helvetica-Bold", 8)
    for day in data["daily"]:
        if y < 20*mm:
            c.showPage(); c.setFillColor(CREAM); c.rect(0,0,W,H,fill=1,stroke=0); y = H-25*mm
            c.setFillColor(NAVY); c.setFont("Helvetica-Bold", 8)
        line = f"{day['date']} ({day['weekday'][:3]}): " + " | ".join(
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


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "performance-timing-backend"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
