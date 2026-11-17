import os
from flask import Flask, jsonify, request, render_template
from services.indicators import validate_indicator
from services.intelligence import investigate_ip



app = Flask(__name__)


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

    if indicator_type == "ip":
        intelligence = investigate_ip(result["value"])

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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

