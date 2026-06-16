"""
Service B — mTLS server that verifies the caller's SPIFFE identity.
Logs caller_identity on every request. Exposes both mTLS (8443) and plain HTTP (8080).
Plain HTTP is the sidecar bypass surface — no identity, no rejection, HTTP 200.
"""
import os
import ssl
import json
import time
import datetime
import threading
import tempfile
from pathlib import Path
from flask import Flask, request, jsonify
import requests
import urllib3
urllib3.disable_warnings()

app = Flask(__name__)

CA_URL = os.environ.get("CA_URL", "http://spiffe_ca:8081")
SPIFFE_ID = os.environ.get("SPIFFE_ID", "spiffe://demo.spiffe.io/service-b")
CERT_DIR = Path(tempfile.mkdtemp())

svid = {}
request_log = []
lock = threading.Lock()


def fetch_svid():
    global svid
    try:
        r = requests.post(f"{CA_URL}/svid/issue", json={"spiffe_id": SPIFFE_ID}, timeout=5)
        if r.status_code == 200:
            svid = r.json()
            (CERT_DIR / "cert.pem").write_text(svid["cert_pem"])
            (CERT_DIR / "key.pem").write_text(svid["key_pem"])
            (CERT_DIR / "ca.pem").write_text(svid["ca_cert_pem"])
            print(f"[B] SVID issued: {SPIFFE_ID} expires={svid['not_after']}")
            return True
    except Exception as e:
        print(f"[B] SVID fetch failed: {e}")
    return False


def rotation_loop():
    while True:
        if svid:
            try:
                expiry = datetime.datetime.fromisoformat(svid["not_after"].replace("Z", ""))
                remaining = (expiry - datetime.datetime.utcnow()).total_seconds()
                if remaining < svid.get("ttl_seconds", 120) / 2:
                    print(f"[B] Rotating SVID (TTL remaining: {remaining:.0f}s)")
                    fetch_svid()
            except Exception as e:
                print(f"[B] Rotation check error: {e}")
        time.sleep(10)


def log_request(caller_identity, status, port, bypass=False):
    with lock:
        request_log.insert(0, {
            "time": datetime.datetime.utcnow().strftime("%H:%M:%S UTC"),
            "status": "BYPASS" if bypass else "OK",
            "caller_identity": caller_identity,
            "port": port,
        })
        if len(request_log) > 50:
            request_log.pop()


# Plain HTTP endpoint — sidecar bypass surface
@app.route("/")
def index_plain():
    log_request(None, "BYPASS", 8080, bypass=True)
    return jsonify({
        "message": "Hello from Service B (PLAIN HTTP)",
        "caller_identity": None,
        "identity_verified": False,
        "warning": "NO mTLS — this is a sidecar bypass attack!",
        "timestamp": datetime.datetime.utcnow().strftime("%H:%M:%S UTC"),
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "spiffe_id": SPIFFE_ID})


@app.route("/request-log")
def get_log():
    with lock:
        return jsonify(request_log[:])


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


# mTLS server thread
def run_mtls_server():
    import http.server
    import ssl as ssl_mod

    class MTLSHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            # Extract caller identity from client cert
            caller_identity = None
            try:
                peer_cert = self.connection.getpeercert()
                if peer_cert:
                    for san_type, san_value in peer_cert.get("subjectAltName", []):
                        if san_type == "URI" and san_value.startswith("spiffe://"):
                            caller_identity = san_value
                            break
            except:
                pass

            log_request(caller_identity, "OK", 8443)
            print(f"[B] mTLS request from {caller_identity or 'unknown'}")

            body = json.dumps({
                "message": "Hello from Service B (mTLS)",
                "caller_identity": caller_identity,
                "identity_verified": caller_identity is not None,
                "timestamp": datetime.datetime.utcnow().strftime("%H:%M:%S UTC"),
            }).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.do_GET()

    # Wait for SVID
    for _ in range(30):
        if (CERT_DIR / "cert.pem").exists():
            break
        time.sleep(1)

    ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT_DIR / "cert.pem"), str(CERT_DIR / "key.pem"))
    ctx.load_verify_locations(str(CERT_DIR / "ca.pem"))
    ctx.verify_mode = ssl_mod.CERT_OPTIONAL  # Accept but don't require client cert

    server = http.server.HTTPServer(("0.0.0.0", 8443), MTLSHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("[B] mTLS server listening on :8443")
    server.serve_forever()


if __name__ == "__main__":
    # Wait for CA
    print("[B] Waiting for CA...")
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
    threading.Thread(target=run_mtls_server, daemon=True).start()

    app.run(host="0.0.0.0", port=8080)
