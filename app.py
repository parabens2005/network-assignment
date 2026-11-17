from services.reports import generate_investigation_pdf
import os
from flask import Flask, jsonify, request, render_template, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from services.indicators import validate_indicator
from services.intelligence import investigate_ip, investigate_domain, investigate_hash



app = Flask(__name__)

# Disable rate limiting only when explicitly running automated tests.
app.config["RATELIMIT_ENABLED"] = (
    os.environ.get("CYBERSENTINEL_TESTING") != "1"
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify(
        status="healthy",
        version="1.1"
    )


@app.route("/api/investigate", methods=["POST"])
@limiter.limit("2 per minute")
def investigate():
    if not request.is_json:
        return jsonify(
            error="Content-Type must be application/json"
        ), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(
            error="A JSON object is required."
        ), 400

    indicator_type = data.get("type")
    indicator_value = data.get("value")

    result = validate_indicator(
        indicator_value,
        indicator_type
    )

    if not result["valid"]:
        return jsonify(
            status="invalid",
            result=result
        ), 400

    if indicator_type in ("ip", "domain", "sha256"):
        if indicator_type == "ip":
            intelligence = investigate_ip(result["value"])
        elif indicator_type == "domain":
            intelligence = investigate_domain(result["value"])
        else:
            intelligence = investigate_hash(result["value"])

        return jsonify(
            status=(
                "completed"
                if intelligence["status"] == "completed"
                else "validated"
            ),
            indicator=result,
            intelligence_status=intelligence["status"],
            intelligence=intelligence,
            verdict="unknown",
            message=intelligence["message"]
        ), 200

    return jsonify(
        status="validated",
        indicator=result,
        intelligence_status="not_queried",
        verdict="unknown",
        message=(
            "Indicator format validated successfully. "
            "Threat intelligence lookup has not been performed."
        )
    ), 200


@app.route("/api/report", methods=["POST"])
@limiter.limit("2 per minute")
def download_report():
    if not request.is_json:
        return jsonify(error="Content-Type must be application/json"), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(error="A JSON object is required."), 400

    indicator_type = data.get("type")
    result = validate_indicator(data.get("value"), indicator_type)

    if not result["valid"]:
        return jsonify(status="invalid", result=result), 400

    if indicator_type == "ip":
        intelligence = investigate_ip(result["value"])
    elif indicator_type == "domain":
        intelligence = investigate_domain(result["value"])
    elif indicator_type == "sha256":
        intelligence = investigate_hash(result["value"])
    else:
        return jsonify(error="Unsupported indicator type."), 400

    report_data = {
        "indicator": result,
        "intelligence_status": intelligence["status"],
        "intelligence": intelligence,
        "verdict": "unknown",
        "message": intelligence.get("message", "")
    }

    pdf_buffer = generate_investigation_pdf(report_data)

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="CyberSentinel_Investigation_Report.pdf"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

