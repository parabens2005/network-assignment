from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <html>
    <head>
        <title>Cybersecurity Cloud Project</title>
    </head>
    <body>
        <h1>Cybersecurity CI/CD Project</h1>
        <h2>Version 1.1</h2>
        <p>Deployed using Docker, GitHub Actions and Google Cloud Run.</p>
        <p>Network and Systems Administration - B9IS121</p>
    </body>
    </html>
    """

@app.route("/health")
def health():
    return jsonify(
        status="healthy",
        version="1.1"
    )

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
