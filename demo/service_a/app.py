"""
Service A — mTLS client. Fetches its SVID from the CA and uses it to call Service B.
Calls Service B every 10 seconds. Supports bypass mode for Scenario 3.
"""
import os
import ssl
import json
import time
import datetime
import threading
import tempfile
import http.client
from pathlib import Path
import requests
import urllib3
urllib3.disable_warnings()

CA_URL = os.environ.get("CA_URL", "http://spiffe_ca:8081")
SERVICE_B_HOST = os.environ.get("SERVICE_B_HOST", "service_b")
SPIFFE_ID = os.environ.get("SPIFFE_ID", "spiffe://demo.spiffe.io/service-a")
CERT_DIR = Path(tempfile.mkdtemp())

svid = {}
call_count = 0


def fetch_svid():
    global svid
    try:
        r = requests.post(f"{CA_URL}/svid/issue", json={"spiffe_id": SPIFFE_ID}, timeout=5)
        if r.status_code == 200:
            svid = r.json()
            (CERT_DIR / "cert.pem").write_text(svid["cert_pem"])
            (CERT_DIR / "key.pem").write_text(svid["key_pem"])
            (CERT_DIR / "ca.pem").write_text(svid["ca_cert_pem"])
            print(f"[A] SVID issued: {SPIFFE_ID} expires={svid['not_after']}")
            return True
    except Exception as e:
        print(f"[A] SVID fetch failed: {e}")
    return False


def call_service_b_mtls():
    """Call Service B over mTLS using our SVID."""
    global call_count
    call_count += 1
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(str(CERT_DIR / "cert.pem"), str(CERT_DIR / "key.pem"))
        ctx.load_verify_locations(str(CERT_DIR / "ca.pem"))
        ctx.check_hostname = False

        conn = http.client.HTTPSConnection(SERVICE_B_HOST, 8443, context=ctx)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = json.loads(resp.read())
        print(f"[A] Call #{call_count} OK: {body.get('caller_identity', 'unknown')}")
        return True
    except Exception as e:
        print(f"[A] Call #{call_count} Failed: {e}")
        return False


def call_service_b_bypass():
    """Call Service B directly over plain HTTP — bypasses mTLS entirely."""
    try:
        r = requests.get(f"http://{SERVICE_B_HOST}:8080/", timeout=5)
        body = r.json()
        print(f"[A] BYPASS call: status={r.status_code} caller_identity={body.get('caller_identity')}")
        return body
    except Exception as e:
        print(f"[A] BYPASS call failed: {e}")
        return None


def rotation_loop():
    while True:
        if svid:
            try:
                expiry = datetime.datetime.fromisoformat(svid["not_after"].replace("Z", ""))
                remaining = (expiry - datetime.datetime.utcnow()).total_seconds()
                if remaining < svid.get("ttl_seconds", 120) / 2:
                    print(f"[A] Rotating SVID (TTL remaining: {remaining:.0f}s)")
                    fetch_svid()
            except Exception as e:
                print(f"[A] Rotation error: {e}")
        time.sleep(10)


def call_loop():
    """Call Service B every 10 seconds."""
    time.sleep(5)  # Let Service B start
    while True:
        if svid and (CERT_DIR / "cert.pem").exists():
            call_service_b_mtls()
        time.sleep(10)


if __name__ == "__main__":
    from flask import Flask, jsonify, request as freq
    app = Flask(__name__)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "spiffe_id": SPIFFE_ID})

    @app.route("/trigger-bypass")
    def trigger_bypass():
        result = call_service_b_bypass()
        return jsonify(result or {"error": "bypass failed"})

    @app.route("/svid-info")
    def svid_info():
        if not svid:
            return jsonify({"error": "No SVID yet"}), 503
        try:
            expiry = datetime.datetime.fromisoformat(svid["not_after"].replace("Z", ""))
            remaining = (expiry - datetime.datetime.utcnow()).total_seconds()
        except:
            remaining = 0
        return jsonify({
            "spiffe_id": svid.get("spiffe_id"),
            "not_before": svid.get("not_before"),
            "not_after": svid.get("not_after"),
            "ttl_seconds": svid.get("ttl_seconds"),
            "ttl_remaining": max(0, int(remaining)),
            "cert_pem": svid.get("cert_pem"),
        })

    # Wait for CA
    print("[A] Waiting for CA...")
    for _ in range(30):
        try:
            r = requests.get(f"{CA_URL}/health", timeout=2)
            if r.status_code == 200:
                break
        except:
            pass
        time.sleep(1)

    fetch_svid()
    threading.Thread(target=rotation_loop, daemon=True).start()
    threading.Thread(target=call_loop, daemon=True).start()

    app.run(host="0.0.0.0", port=8080)
