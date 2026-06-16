# Zero Trust Beyond BeyondCorp
### Workload Identity, SPIFFE/SPIRE Failure Modes, and the Naming Problem

> **Thesis claim:** Trust domain naming is the structurally dominant failure surface in SPIFFE/SPIRE deployments — not cryptography. Naming errors are silent, non-self-healing, and unaddressed by NIST SP 800-207A.

---

## What This Project Is

A research presentation and live technical demonstration built for a master's-level security audience. It argues that Google's BeyondCorp model, while foundational for Zero Trust, leaves machine-to-machine identity unsolved — and that SPIFFE/SPIRE, the CNCF standard that fills this gap, introduces its own failure class that existing literature has not systematically examined.

The demo reproduces three distinct failure scenarios in a fully containerised environment using real X.509 certificates, real mTLS enforcement, and real TTL expiry — no mocks.

---

## The Core Argument

Most Zero Trust literature focuses on cryptographic correctness. Key rotation, attestation chains, certificate revocation — these failures are **self-signaling**: a bad key breaks the TLS handshake immediately and visibly.

Trust domain naming failures are different. A wrong trust domain causes mTLS to either:
- **Succeed between the wrong parties** (cross-domain confusion), or
- **Fail silently at the application layer** — returning HTTP 200 with a null caller identity

Neither outcome produces an error that the application sees. This makes naming errors operationally unrecoverable without out-of-band tooling — and structurally more dangerous than cryptographic failures, which at least announce themselves.

**NIST SP 800-207A (Sept 2023)** explicitly references SPIFFE SVIDs as a workload identity mechanism but provides no normative guidance on trust domain naming conventions, CI-layer validation of registration YAMLs, or alerting on bundle endpoint connectivity loss. This is the gap this project targets.

---

## Demo Scenarios

The demo environment runs four Docker containers: a SPIFFE CA, Service A, Service B, and a web dashboard at `localhost:7000`.

| Scenario | What It Tests | Key Observable |
|---|---|---|
| **S1: Happy Path** | Correct SVID issuance and mTLS | `caller_identity` field populated, TTL visible |
| **S2: Rotation Gap** | CA stopped mid-TTL | Service calls fail as certificates expire |
| **S3: Sidecar Bypass** | Direct HTTP, no sidecar | HTTP 200 returned, `caller_identity` is `null` |

Scenario 3 is the thesis in action: **the attacker's success is invisible to the application layer.** Status code alone is insufficient for security auditing in a SPIFFE environment.

---

## Tech Stack

| Component | Technology |
|---|---|
| Certificate issuance | Python `cryptography` library (X.509, real SVIDs) |
| Transport security | mTLS (mutual TLS) |
| Containerisation | Docker + Docker Compose |
| Identity standard | SPIFFE (Secure Production Identity Framework for Everyone) |
| Standards basis | NIST SP 800-207, SP 800-207A, SP 1800-35 |

> **No SPIRE binaries required.** The CA is implemented directly in Python to ensure the demo is fully reproducible on any Docker host without external dependencies.

---

## Running the Demo

### Prerequisites

- Docker and Docker Compose installed
- Ports 7000 free on localhost

### Start the environment

```bash
git clone https://github.com/YOUR_USERNAME/zero-trust-workload-identity
cd zero-trust-workload-identity/demo
docker compose up --build
```

Open `http://localhost:7000` for the live dashboard.

### Run the scenarios

```bash
# S1: Happy path — verify SVID issuance
docker exec service_a python client.py --mode happy

# S2: Rotation gap — stop the CA and watch TTL expire
docker stop spiffe_ca
# Wait ~60 seconds, then check the dashboard

# S3: Sidecar bypass — direct HTTP call, no mTLS
docker exec service_a python client.py --mode bypass
# Observe: HTTP 200, caller_identity = null
```

---

## Repository Structure

```
zero-trust-workload-identity/
├── README.md
├── docs/
│   ├── ZeroTrust_ThesisLevel.pptx      # 25-slide main presentation
│   └── ZeroTrust_Demo_Walkthrough.pptx # 10-slide live demo guide
├── demo/
│   ├── docker-compose.yml
│   ├── spiffe_ca/                       # Python X.509 CA
│   ├── service_a/                       # mTLS client
│   ├── service_b/                       # mTLS server with identity logging
│   └── dashboard/                       # Web UI at localhost:7000
└── research-notes/
    ├── nist-gap-analysis.md             # Section-by-section 800-207A analysis
    ├── threat-model.md                  # STRIDE analysis for SPIFFE/SPIRE
    └── failure-taxonomy.md              # Taxonomy of operator vs. attacker failures
```

---

## Research Notes

The `/research-notes` folder contains standalone writeups that go deeper than the slides:

- **[NIST Gap Analysis](research-notes/nist-gap-analysis.md)** — what SP 800-207A mandates, what it leaves unspecified, and proposed standard extensions
- **[Threat Model](research-notes/threat-model.md)** — STRIDE applied to SPIFFE/SPIRE components
- **[Failure Taxonomy](research-notes/failure-taxonomy.md)** — classifying SPIFFE failures by operator error vs. attacker action

---

## Key Concepts

If you're new to this space, these are the terms that matter:

| Term | Plain English |
|---|---|
| **SPIFFE ID** | A URI that uniquely identifies a workload: `spiffe://trust-domain/service-name` |
| **SVID** | The X.509 certificate that carries a SPIFFE ID — the workload's cryptographic identity |
| **Trust domain** | The administrative boundary within which identities are trusted |
| **mTLS** | Both sides of a connection present certificates — not just the server |
| **Sidecar** | A proxy container that handles mTLS on behalf of the workload |
| **Workload API** | The SPIRE interface through which workloads receive their SVIDs |
| **TTL** | How long an SVID is valid before it must be rotated — typically 1 hour |

---

## What I Learned (SOC Relevance)

This project sharpened several capabilities directly applicable to security operations:

**Threat modelling under incomplete information.** Applying STRIDE to SPIFFE/SPIRE required reasoning about attacker capability models where the attacker may be an operator making a configuration error, not an external adversary.

**Signal vs. noise in access logs.** The sidecar bypass scenario demonstrates that HTTP 200 is not a security signal in a Zero Trust environment. A SOC analyst monitoring a SPIFFE-protected service needs to alert on `caller_identity = null`, not on 4xx/5xx codes.

**Standards gap analysis.** Reading NIST SP 800-207A section by section — not just citing it — built a habit of distinguishing what a standard *requires* from what it *assumes*.

**Silent failures are the hardest to detect.** The most dangerous failure in this system produces no error. This generalises: in security, the absence of a signal is itself a signal worth alerting on.

---

## Presentation

The full 25-slide deck (`docs/ZeroTrust_ThesisLevel.pptx`) covers:

1. NIST Standards Lineage (SP 800-207 → 800-207A → SP 1800-35)
2. BeyondCorp limitations for machine-to-machine identity
3. SPIFFE/SPIRE primitives and attestation model
4. Cross-cloud federation without a shared root CA
5. Short-lived credentials and TTL rotation
6. Failure modes and STRIDE threat analysis
7. Academic literature review and research gap
8. Thesis contribution and NIST gap analysis
9. Mitigations framework (Day 0 / Day 1 / Day 2)

---

## Academic Context

This project was developed as part of a master's programme in information security. The research contribution is original: no prior work identified trust domain naming as a distinct, systematically analysable failure surface in SPIFFE/SPIRE deployments.

The simulation environment was built from scratch using Python's `cryptography` library rather than SPIRE binaries, ensuring full transparency and reproducibility of the experimental results.

---

## References

- NIST SP 800-207 — Zero Trust Architecture
- NIST SP 800-207A — A Zero Trust Architecture Model for Access Control in Cloud-Native Systems (Sept 2023)
- NIST NCCoE SP 1800-35 — Implementing a Zero Trust Architecture
- SPIFFE Specification — https://github.com/spiffe/spiffe
- CNCF SPIRE Documentation — https://spiffe.io/docs/latest/spire-about/

---

*Built by Kundan, Rutuj, and Siddhartha as part of master's-level security research.*
