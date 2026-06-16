# NIST SP 800-207A: Section-by-Section Gap Analysis

**Standard:** NIST SP 800-207A — A Zero Trust Architecture Model for Access Control in Cloud-Native Systems  
**Published:** September 2023  
**Relevance:** First NIST document to explicitly reference SPIFFE SVIDs as a workload identity mechanism

---

## What the Standard Gets Right

### Section 4.2 — Workload Identity Requirements

> Workloads MUST be issued SVIDs. SVIDs MUST be rotated before expiry.

This is precise and normative. It establishes SVID-based identity as the mandatory mechanism for workload authentication in Zero Trust cloud-native environments. The rotation requirement directly motivates SPIRE's short-TTL design (typically 1 hour).

**Assessment:** Complete. No gap.

### Section 4.3 — SVID Format Requirements

> SVIDs MUST embed the SPIFFE ID in the Subject Alternative Name (SAN) URI field. The SPIFFE ID MUST conform to the `spiffe://` URI scheme.

This pins down the cryptographic binding between identity and certificate. An SVID that does not carry a valid SPIFFE URI in the SAN is non-conformant.

**Assessment:** Complete. No gap.

### Section 5.1 — Trust Bundle Exchange

> Trust bundles MUST be exchanged via authenticated bundle endpoints. Bundle endpoint authentication MUST use HTTPS with server certificate validation.

This addresses the cross-domain federation case and prevents unauthenticated bundle injection.

**Assessment:** Mostly complete. The standard specifies *how* to exchange bundles but does not specify alerting requirements for bundle endpoint connectivity loss before SVID TTL expiry — a meaningful operational gap (see below).

---

## Where the Standard Falls Silent

### Gap 1: Trust Domain Naming Conventions

The standard specifies that SPIFFE IDs must use the `spiffe://` URI scheme and that the authority component is the trust domain. It does **not** specify:

- Naming conventions for trust domains (format, length, allowed characters beyond the URI spec)
- Uniqueness scope requirements (are trust domains expected to be globally unique? Per-organisation?)
- Environment segregation requirements (must `prod` and `staging` use different trust domains?)
- Whether trust domain names should be human-readable or opaque identifiers

**Operational consequence:** Two organisations can both be fully compliant with 800-207A while using identical trust domain names (`example.org`). An operator can misconfigure a registration entry with the wrong trust domain and be compliant with every MUST in the standard.

**Proposed addition:** A SHOULD-level requirement specifying that trust domain names SHOULD be scoped to the organisation's registered domain name and SHOULD include an environment qualifier (e.g., `prod.example.org`, `staging.example.org`).

---

### Gap 2: CI-Layer Validation of Registration Entries

SPIRE workload registration is typically managed via YAML files that define workload selectors and their associated SPIFFE IDs. The standard mandates what SVIDs must contain but says nothing about:

- Validation of registration entry YAMLs before deployment
- Linting of trust domain strings in registration entries
- Preventing deployment of entries that reference non-existent trust domains
- Detecting duplicate or conflicting registrations

**Operational consequence:** A typo in a registration YAML (`prod.example.org` → `prod.exmaple.org`) produces a silently incorrect SPIFFE ID that passes all cryptographic checks. The SVID is valid; it just identifies the wrong workload in the wrong domain.

**Proposed addition:** A SHOULD-level requirement that organisations implement CI-layer linting of SPIRE registration entries, validating trust domain strings against a canonical registry before deployment.

---

### Gap 3: Bundle Endpoint Connectivity Alerting

Section 5.1 specifies how trust bundles must be exchanged but does not specify operational requirements for detecting bundle endpoint failures before they cause SVID expiry.

**The problem:** If a bundle endpoint becomes unreachable, SPIRE agents cannot refresh their trust bundle. When SVID TTLs expire, the entire service mesh loses its ability to verify identities. This is the Rotation Gap attack scenario (S2 in the demo).

**Operational consequence:** There is no standard-mandated monitoring requirement that would alert operators to bundle endpoint failures *before* the TTL expiry window closes. By the time the failure is visible (service calls start failing), the window for graceful recovery may have passed.

**Proposed addition:** A MUST-level requirement that SPIRE deployments implement alerting when bundle endpoint connectivity is lost with more than one TTL period remaining before the next required refresh.

---

## Summary Table

| Section | Requirement | Gap? |
|---|---|---|
| 4.2 | SVID issuance and rotation | None |
| 4.3 | SPIFFE ID in SAN URI | None |
| 5.1 | Bundle endpoint authentication | Partial (no connectivity alerting) |
| — | Trust domain naming conventions | **Missing** |
| — | CI validation of registration entries | **Missing** |
| — | Bundle endpoint loss alerting | **Missing** |

---

## Relation to This Work

The three gaps above map directly to the three mitigation categories proposed in the main presentation:

- **Day 0 (design):** Trust domain naming conventions
- **Day 1 (deployment):** CI-layer registration entry linting
- **Day 2 (operations):** Bundle endpoint connectivity monitoring

The thesis claim — that naming is the dominant failure surface — is partly supported by the standards gap: 800-207A's cryptographic requirements are precise and complete, while its operational naming requirements are absent. The standard implicitly treats naming as solved, when operationally it is the hardest thing to enforce.
