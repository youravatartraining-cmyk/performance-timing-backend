"""
Performance Timing — Backend Service
Avatar Training

Deployed on Render. Currently handles:
  POST /api/subscribe  — writes intake form submissions (name, email, DOB)
                          to MailerLite, replacing the Cloudflare Pages
                          Function that couldn't work on a drag-and-drop
                          deployment (Cloudflare Functions require Wrangler,
                          which this site's deploy method doesn't use).

NOT YET BUILT (next session): the Stripe webhook endpoint that triggers
report generation only after payment confirms. This file is structured so
that endpoint can be added here directly — same service, same deployment,
no new infrastructure needed.

Required environment variables (set in Render dashboard, never in code):
  MAILERLITE_API_KEY   — MailerLite: Integrations -> API -> generate token
"""

import os
import re
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

MAILERLITE_GROUP_ID = "195545324381538237"  # Performance Timing Subscribers
DOB_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def cors_headers(resp):
    """Allow the avtrlife.com site (different domain, Cloudflare Pages) to
    call this API. Tightened to the real domain rather than left wide open."""
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
        # Fails loudly — if this ever shows up, the env var isn't set in
        # Render yet. Never silently drop a signup.
        return cors_headers(jsonify({"error": "Server not configured (missing MailerLite key)"})), 500

    ml_response = requests.post(
        "https://connect.mailerlite.com/api/subscribers",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        json={
            "email": email,
            "fields": {"name": name, "date_of_birth": dob},
            "groups": [MAILERLITE_GROUP_ID],
        },
        timeout=10,
    )

    if not ml_response.ok:
        return cors_headers(jsonify({"error": "MailerLite write failed", "detail": ml_response.text})), 502

    return cors_headers(jsonify({"success": True}))


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "performance-timing-backend"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
