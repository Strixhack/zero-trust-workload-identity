# STRIDE Threat Model: SPIFFE/SPIRE Components

**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Scope:** SPIRE Server, SPIRE Agent, Workload API, Trust Bundle endpoint, mTLS channel

---

## Component Map

```
[Workload] ←── Workload API ───→ [SPIRE Agent] ←── Attestation ───→ [SPIRE Server]
                                                                           │
                                                                    [Trust Bundle]
                                                                           │
[Workload A] ←────────────── mTLS ──────────────→ [Workload B]
```

---

## STRIDE Analysis

### SPIRE Server

| Threat | Category | Likelihood | Impact | Notes |
|---|---|---|---|---|
| Attacker registers fraudulent workload entry | Spoofing | Low | Critical | Requires API access; mitigated by RBAC |
| Registration entry YAML tampered in CI pipeline | Tampering | Medium | High | **Primary finding:** no standard-mandated lint |
| No audit log of registration changes | Repudiation | Medium | Medium | Depends on deployment config |
| Server private key exfiltrated | Information Disclosure | Low | Critical | HSM mitigates |
| Server unavailable causes SVID rotation failure | Denial of Service | Medium | High | HA deployment mitigates |
| Compromised server issues SVIDs to wrong workloads | Elevation of Privilege | Low | Critical | Upstream CA compromise |

### SPIRE Agent

| Threat | Category | Likelihood | Impact | Notes |
|---|---|---|---|---|
| Agent node attestation bypassed | Spoofing | Low | High | Platform-specific; TPM mitigates |
| Agent cache poisoned with wrong SVIDs | Tampering | Low | High | Requires local root access |
| Agent logs workload identity silently | Repudiation | Low | Low | Workload API is local socket |
| SVID material readable from agent cache | Information Disclosure | Medium | High | File permission controls |
| Agent killed, workload cannot get SVID | Denial of Service | Medium | Medium | Restart policy mitigates |
| Agent assigned wrong node selectors | Elevation of Privilege | Medium | High | Operator error; naming gap |

### Workload API (Unix socket)

| Threat | Category | Likelihood | Impact | Notes |
|---|---|---|---|---|
| Wrong workload reads another's SVID | Spoofing | Low | Critical | Selector mismatch; requires kernel bypass |
| Socket permissions allow unintended access | Tampering | Low | High | File permission controls |
| No workload-level API audit log | Repudiation | Medium | Low | Acceptable given socket locality |

### mTLS Channel

| Threat | Category | Likelihood | Impact | Notes |
|---|---|---|---|---|
| Sidecar bypassed, direct HTTP used | Spoofing | **High** | **Critical** | **Demo S3: silent 200 OK** |
| Certificate pinning not enforced | Tampering | Medium | High | Depends on proxy config |
| Traffic readable if sidecar termination mis-scoped | Information Disclosure | Low | Medium | Mesh config issue |
| mTLS handshake failure cascades | Denial of Service | Medium | Medium | CA availability dependency |
| Wrong trust domain accepted by permissive policy | Elevation of Privilege | **High** | **Critical** | **Core naming thesis** |

### Trust Bundle Endpoint

| Threat | Category | Likelihood | Impact | Notes |
|---|---|---|---|---|
| Bundle endpoint serves attacker's root CA | Spoofing | Low | Critical | HTTPS auth mitigates |
| Bundle stale due to connectivity loss | Tampering | **Medium** | **High** | **Demo S2: rotation gap** |
| No alerting on endpoint loss | Denial of Service | Medium | High | Standards gap (800-207A) |

---

## High-Priority Threats (Red)

Three threats stand out as both high-likelihood and high-impact in real deployments:

**1. Sidecar bypass (mTLS — Spoofing)**
An operator or developer connecting directly to a service port bypasses the sidecar entirely. The service receives the request and returns HTTP 200. The `caller_identity` field in the access log is `null`. No error is produced. This is the thesis scenario: the attack is indistinguishable from a legitimate call at the application layer.

*Mitigation:* Enforce STRICT mTLS mode in the service mesh. Reject any connection that does not present a valid SVID. This converts a silent failure into a visible one (connection refused).

**2. Wrong trust domain accepted (mTLS — Elevation of Privilege)**
A misconfigured registration entry assigns the wrong trust domain to a workload. The SVID is cryptographically valid but semantically incorrect. Policy engines that check the SPIFFE ID string (e.g., OPA, Envoy RBAC) may accept or reject based on the wrong identity.

*Mitigation:* CI-layer linting of registration YAMLs. Trust domain strings should be validated against a canonical registry before deployment.

**3. Bundle endpoint connectivity loss (Trust Bundle — DoS)**
If the SPIRE server's bundle endpoint becomes unreachable, agents cannot refresh their trust bundle. When SVID TTLs expire, mTLS handshakes fail cluster-wide. This is a timed denial of service — the window from connectivity loss to outage is exactly one TTL period.

*Mitigation:* Monitor bundle endpoint connectivity. Alert when loss is detected with more than one TTL period remaining. Consider bundle caching with a longer validity window for disaster recovery.

---

## Threat Comparison: Crypto vs. Naming Failures

| Property | Crypto Failure | Naming Failure |
|---|---|---|
| Example | Expired SVID | Wrong trust domain |
| Application-layer signal | TLS handshake failure (visible) | HTTP 200, null identity (silent) |
| Self-healing | Yes (rotation restores) | No (operator YAML change required) |
| Time to detect | Immediate | Depends on audit log review |
| NIST 800-207A guidance | Precise and normative | Absent |

This comparison is the structural basis for the thesis claim: naming failures are operationally harder to detect and recover from than cryptographic failures, making them the dominant failure surface in practice.
