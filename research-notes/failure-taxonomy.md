# Failure Taxonomy: SPIFFE/SPIRE Deployment Failures

A structured classification of failure modes in SPIFFE/SPIRE deployments, distinguishing between attacker-induced failures and operator-induced failures. This distinction is largely absent from existing literature, which focuses on attacker capability models.

---

## Why the Distinction Matters

Most security failure taxonomies ask: *what can an attacker do?*

In workload identity systems, a more operationally relevant question is: *what can an operator misconfigure that produces the same outcome as a successful attack?*

A trust domain misconfiguration does not require an adversary. An operator typo in a registration YAML can silently disable identity verification for an entire service — producing the same null-identity outcome as a deliberate sidecar bypass attack.

This has two consequences:
1. **Detection:** Attacker-induced failures may leave adversarial indicators (unexpected source IPs, anomalous timing). Operator-induced failures look exactly like normal deployments.
2. **Response:** Attacker failures trigger incident response. Operator failures may be categorised as bugs, delaying the security response.

---

## Taxonomy

### Class A: Cryptographic Failures

Failures in the cryptographic layer — key material, certificate validity, or CA availability.

| Failure | Trigger | Signal | Self-healing? |
|---|---|---|---|
| SVID expired | CA unavailable at rotation time | TLS handshake failure | Yes, when CA recovers |
| Root CA key compromised | Attacker exfiltrates key | Valid-looking SVIDs from attacker | No — full re-issuance required |
| SVID issued to wrong node | Node attestation bypassed | Cryptographically valid, semantically wrong | No — registration fix required |
| Bundle endpoint serves wrong CA | MITM or misconfiguration | Trust verification failure | Depends on detection speed |

**Characteristic:** Class A failures are mostly self-signaling. An expired SVID produces an immediate TLS handshake failure. A compromised CA is detectable via certificate transparency or unexpected SVID issuance patterns.

---

### Class B: Naming Failures (Operator-Induced)

Failures in the trust domain naming and registration layer — where the cryptographic material is correct but the identity it encodes is wrong.

| Failure | Trigger | Signal | Self-healing? |
|---|---|---|---|
| Wrong trust domain in registration YAML | Operator typo | **None** — HTTP 200, null identity | No — YAML fix required |
| Environment trust domain collision | `prod` and `staging` share a domain | Cross-environment SVID acceptance | No — naming redesign required |
| Missing registration entry | Operator omission | TLS handshake failure (service unregistered) | No — registration required |
| Stale registration entry after service rename | Operator oversight | Old SPIFFE ID still valid, new name unregistered | No — manual update required |

**Characteristic:** Class B failures are silent or ambiguous. A wrong trust domain produces no application-layer error. A missing registration entry looks like a network failure, not an identity failure.

---

### Class C: Policy Failures

Failures in the policy layer — where identities are correctly issued but policy engines make incorrect access decisions.

| Failure | Trigger | Signal | Self-healing? |
|---|---|---|---|
| OPA/Envoy policy allows wrong SPIFFE ID | Overly permissive policy rule | Authorised calls from wrong workload | No — policy fix required |
| Policy not updated after SPIFFE ID change | Operator oversight | Legitimate workload denied; wrong workload allowed | No — manual update required |
| Trust domain not validated in policy | Policy only checks path, not domain | Cross-domain spoofing accepted | No — policy rewrite required |

**Characteristic:** Class C failures are the most dangerous because they may allow access to proceed normally while authorising the wrong workload. A policy that checks `spiffe://*/payment-service` instead of `spiffe://prod.example.org/payment-service` accepts any workload named `payment-service` in any trust domain.

---

### Class D: Operational Failures

Failures in the operational layer — monitoring, alerting, and incident response gaps that amplify other failure classes.

| Failure | Trigger | Signal | Self-healing? |
|---|---|---|---|
| No alerting on bundle endpoint loss | Infrastructure issue | None until SVID TTL expiry | No |
| No audit log review process | Process gap | Sidecar bypass goes undetected indefinitely | No |
| Caller identity not logged | Service configuration | Forensic gap in incident response | No |
| No CI lint of registration entries | Process gap | Naming errors reach production | No |

**Characteristic:** Class D failures are not failures in themselves — they are the absence of controls that would detect Classes A, B, and C. They convert recoverable failures into unrecoverable ones by extending the detection window.

---

## Cross-Reference: Demo Scenarios

| Scenario | Class | Failure | Observable |
|---|---|---|---|
| S1: Happy Path | — | No failure | `caller_identity` populated, TTL visible |
| S2: Rotation Gap | Class A + Class D | CA unavailable, no alerting | Service calls fail at TTL expiry |
| S3: Sidecar Bypass | Class B + Class D | Naming/config gap, no audit | HTTP 200, `caller_identity = null` |

---

## Implications for SOC Detection

A SOC analyst monitoring a SPIFFE-protected environment should treat the following as security signals, not operational noise:

| Signal | Likely Class | Response |
|---|---|---|
| `caller_identity = null` in access logs | Class B or D | Investigate service mesh config; check sidecar status |
| TLS handshake failures cluster-wide | Class A | Check SPIRE server and bundle endpoint availability |
| SVID issuance spike from unexpected workload | Class A | Investigate node attestation; possible CA compromise |
| New SPIFFE ID appearing in policy logs | Class C | Verify registration entry is authorised |
| Bundle endpoint connectivity loss | Class D | Alert immediately; TTL expiry window has started |

The key insight: in a correctly operating SPIFFE environment, `caller_identity` should **never** be null on an mTLS-protected endpoint. A null value is an indicator of compromise or misconfiguration — it should trigger the same response either way.
