"""
Dashboard API — aggregates data from all services for the web UI.
"""
import os
import requests
import urllib3
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
urllib3.disable_warnings()

app = Flask(__name__, static_folder="static")
CORS(app)

CA_URL = os.environ.get("CA_URL", "http://spiffe_ca:8081")
SERVICE_A_URL = os.environ.get("SERVICE_A_URL", "http://service_a:8080")
SERVICE_B_URL = os.environ.get("SERVICE_B_URL", "http://service_b:8080")


def safe_get(url, timeout=3):
    try:
        r = requests.get(url, timeout=timeout)
        return r.json(), r.status_code
    except Exception as e:
        return {"error": str(e)}, 503


def safe_post(url, data, timeout=3):
    try:
        r = requests.post(url, json=data, timeout=timeout)
        return r.json(), r.status_code
    except Exception as e:
        return {"error": str(e)}, 503


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/status")
def status():
    ca, ca_code = safe_get(f"{CA_URL}/health")
    svc_b, b_code = safe_get(f"{SERVICE_B_URL}/health")
    return jsonify({
        "ca": {"healthy": ca_code == 200, "data": ca},
        "service_b": {"healthy": b_code == 200, "data": svc_b},
    })


@app.route("/api/request-log")
def request_log():
    data, _ = safe_get(f"{SERVICE_B_URL}/request-log")
    return jsonify(data)


@app.route("/api/svid/service-a")
def svid_a():
    data, code = safe_get(f"{SERVICE_A_URL}/svid-info")
    return jsonify(data), code


@app.route("/api/svid/service-b")
def svid_b():
    data, code = safe_get(f"{SERVICE_B_URL}/svid-info")
    return jsonify(data), code


@app.route("/api/svid/issue", methods=["POST"])
def issue_svid():
    from flask import request
    body = request.json or {}
    data, code = safe_post(f"{CA_URL}/svid/issue", body)
    return jsonify(data), code


@app.route("/api/registered-entries")
def registered_entries():
    data, code = safe_get(f"{CA_URL}/registered-entries")
    return jsonify(data), code


@app.route("/api/ca/status")
def ca_status():
    data, code = safe_get(f"{CA_URL}/health")
    return jsonify({"healthy": code == 200, "data": data}), 200


@app.route("/api/bypass/trigger")
def trigger_bypass():
    data, code = safe_get(f"{SERVICE_A_URL}/trigger-bypass")
    return jsonify(data), code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
