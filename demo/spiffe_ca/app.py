"""
SPIFFE CA — issues real X.509 SVIDs with SPIFFE URIs in the SAN field.
Uses Python cryptography library. No SPIRE binaries required.
"""
import os
import json
import time
import datetime
from pathlib import Path
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import UniformResourceIdentifier

app = Flask(__name__)
CERT_DIR = Path("/certs")
CERT_DIR.mkdir(exist_ok=True)

TTL_SECONDS = int(os.environ.get("SVID_TTL", 120))
TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "demo.spiffe.io")

# Generate CA key and self-signed cert on startup
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"SPIFFE CA - {TRUST_DOMAIN}")])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

# Write CA cert to shared volume
ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
(CERT_DIR / "ca.crt").write_bytes(ca_cert_pem)
print(f"[CA] Started. Trust domain: {TRUST_DOMAIN}. TTL: {TTL_SECONDS}s")


def issue_svid(spiffe_id: str) -> dict:
    """Issue a real X.509 SVID with the SPIFFE ID in the SAN URI field."""
    workload_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    expiry = now + datetime.timedelta(seconds=TTL_SECONDS)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spiffe_id)]))
        .issuer_name(ca_cert.subject)
        .public_key(workload_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_id)
            ]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = workload_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    return {
        "spiffe_id": spiffe_id,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "ca_cert_pem": ca_cert_pem.decode(),
        "not_before": now.isoformat() + "Z",
        "not_after": expiry.isoformat() + "Z",
        "ttl_seconds": TTL_SECONDS,
    }


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "trust_domain": TRUST_DOMAIN})


@app.route("/svid/issue", methods=["POST"])
def issue():
    data = request.json or {}
    spiffe_id = data.get("spiffe_id")
    if not spiffe_id or not spiffe_id.startswith("spiffe://"):
        return jsonify({"error": "Invalid or missing spiffe_id"}), 400
    print(f"[CA] Issuing SVID for {spiffe_id}")
    return jsonify(issue_svid(spiffe_id))


@app.route("/ca/cert")
def get_ca_cert():
    return ca_cert_pem.decode(), 200, {"Content-Type": "text/plain"}


@app.route("/registered-entries")
def registered_entries():
    return jsonify([
        {"spiffe_id": f"spiffe://{TRUST_DOMAIN}/service-a", "selector": "container:service-a", "ttl": TTL_SECONDS},
        {"spiffe_id": f"spiffe://{TRUST_DOMAIN}/service-b", "selector": "container:service-b", "ttl": TTL_SECONDS},
    ])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
