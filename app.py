from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from detector import confidence_for, scan_url

app = Flask(__name__)


def result_status(score: int) -> str:
    if score < 25:
        return "Safe"
    if score < 60:
        return "Suspicious"
    return "Phishing"


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "phishguard"})


@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get("url", "")).strip()

    try:
        result = scan_url(raw_url)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(
        {
            "url": result.submitted_url,
            "normalized_url": result.normalized_url,
            "hostname": result.hostname,
            "score": result.score,
            "status": result_status(result.score),
            "risk_level": result.level,
            "verdict": result.verdict,
            "confidence": confidence_for(result),
            "signals": [
                {
                    "label": signal.label,
                    "detail": signal.detail,
                    "points": signal.points,
                    "severity": signal.severity,
                }
                for signal in result.signals
            ],
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("port", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)