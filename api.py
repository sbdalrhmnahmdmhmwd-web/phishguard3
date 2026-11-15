"""PhishGuard API. Run locally: python api.py   |  Production: gunicorn -b 127.0.0.1:8000 api:app"""
from flask import Flask, jsonify, request
from analyzer import analyze

app = Flask(__name__)


@app.after_request
def cors(resp):  # lets a separate website call this API
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze_url():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(analyze(data.get("url", "")))
    except ValueError as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
