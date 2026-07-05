# Cryptographic Discovery & CBOM Tooling — Landscape

How QuantScan relates to other post-quantum cryptography (PQC) readiness,
cryptographic-discovery, and Cryptography Bill of Materials (CBOM) tools.

> Star counts and vendor details are approximate, from a survey in **July 2026**.
> Treat them as directional, not authoritative.

## The shared foundation

QuantScan and nearly every tool here orbit the same standards:

- **CycloneDX CBOM** — the Cryptography Bill of Materials format (originated by IBM,
  now under OWASP / PQCA). QuantScan reads and writes this.
- **NIST IR 8547** (PQC transition), **CNSA 2.0** (deadlines), and
  **FIPS 203 / 204 / 205** (ML-KEM / ML-DSA / SLH-DSA) — the guidance QuantScan maps
  findings to.

## Open source (GitHub)

The center of gravity is the **`cbomkit` org** (formerly IBM Research, now PQCA):

| Repo | ★ | Role |
|------|---|------|
| `cbomkit/cbomkit` | ~111 | Full CBOM toolset: service + web UI + DB (QuantScan's `--purl` backend) |
| `IBM/CBOM` | ~110 | Original CBOM spec/tooling (upstreamed into CycloneDX 1.6) |
| `cbomkit/sonar-cryptography` | ~74 | SonarQube plugin — **source-code** crypto detection (Java/Python); the engine behind CBOMkit |
| `cbomkit/cbomkit-theia` | — | **Filesystem / container-image** scanner (certs, keys, OpenSSL config) — *vendored in-process by QuantScan* |
| `cbomkit/cbomkit-action` | ~15 | GitHub Action wrapper for CI |

Independent / adjacent projects:

| Repo | ★ | Angle |
|------|---|-------|
| `Santandersecurityresearch/cryptobom-forge` | ~36 | Turns **CodeQL** multi-repo analysis output into a CBOM |
| `SEG-UNIBE/BF-CBOM` | ~10 | Generate / understand / **compare** CBOMs (academic) |
| `SEG-UNIBE/cbombench` | ~3 | Benchmarking testbed for CBOM generators |
| `anthonyharrison/cbom4cert` | ~0 | CBOM from X.509 certificates specifically |
| `GowithKeya/Quantum-Safe-Scanner`, `OmniTrustILM/cbom-repository`, `ibrahim199924/C-BOM` | 0–2 | Small CBOM generators / storage repositories |
| `RiccardoBiosas/awesome-cbom` | — | Curated index (currently mostly a skeleton) |

Adjacent but **not** discovery: **Open Quantum Safe** (`liboqs`, `oqs-provider`) provides
the PQC *algorithms* to migrate *to*, not an inventory of what you run.

**Takeaway:** most open-source tools stop at *generating* a CBOM. The scoring,
risk-classification, compliance-roadmap, and report layers are comparatively rare —
which is where QuantScan concentrates its value.

## Commercial

| Vendor / Product | Discovery method |
|------------------|------------------|
| **IBM Quantum Safe** (Explorer / Advisor / Remediator) | Static code analysis + runtime TLS/cert monitoring — the origin of CBOM |
| **Keyfactor** (acquired **InfoSec Global** AgileSec Analytics, 2025) | Agent-based host scanning, CBOM, a **PQC readiness score**, remediation guidance |
| **SandboxAQ** (acquired **Cryptosense**) | Crypto discovery / security suite |
| **AppViewX** AVX ONE PQC Assessment | Certificate-lifecycle-centric visibility |
| **QryptoCyber** | Scans networks, codebases, DBs → CBOM |
| **QuSecure** QuProtect R3 | Cross-environment inventory + crypto orchestration |
| **QCecuring**, **Encryption Consulting** CBOM Secure | Enterprise CBOM discovery / inventory |
| Cert/CLM incumbents: **DigiCert, Venafi (CyberArk), Entrust, Thales, PQShield, Cisco, Palo Alto** | Certificate + key management extended toward PQC |

Closest parallels: **Keyfactor's "PQC readiness score"** mirrors QuantScan's 0–100 score,
and **IBM Quantum Safe** shares the same CBOM lineage.

## Discovery techniques (how tools differ)

1. **Source-code static analysis** — CBOMkit / sonar-cryptography, cryptobom-forge (CodeQL), IBM Explorer.
2. **Filesystem / binary / container-image scanning** — cbomkit-theia *(QuantScan uses this)*.
3. **Network / passive TLS sniffing** — mostly commercial.
4. **Agent-based host scanning** — Keyfactor / InfoSec Global.
5. **Certificate-focused** — cbom4cert, the CLM vendors.

QuantScan covers **(2)** natively (in-process theia) and **(1)** via the CBOMkit service.
It does **not** do network sniffing or agent-based host discovery.

## Where QuantScan sits

- **Positioning** — an open-source, single-binary **CBOM consumer + scorer + reporter**
  that orchestrates existing detection engines (theia in-process, CBOMkit over HTTP)
  rather than reinventing detection.
- **Differentiators vs. OSS peers** — deterministic four-class quantum-risk scoring,
  NIST IR 8547 / CNSA 2.0 + control-framework mapping (PCI DSS, SOC 2, ISO 27001), and
  auditor-ready PDF/HTML reports — layers most OSS CBOM tools lack.
- **Gaps vs. commercial** — no network/passive discovery, no agent fleet, no continuous
  monitoring / database / dashboard; source-code depth is only as good as the CBOMkit
  service it points at.

## Sources

- [postquantum.com — Cryptographic Inventory Vendors](https://postquantum.com/post-quantum/cryptographic-inventory-vendors/)
- [Encryption Consulting — Cryptographic Inventory Vendors](https://www.encryptionconsulting.com/cryptographic-inventory-vendors/)
- [Keyfactor / InfoSec Global — AgileSec Analytics](https://www.infosecglobal.com/products/agilesec-analytics)
- [QuSecure](https://www.qusecure.com/)
- [QryptoCyber](https://qryptocyber.com/)
- [QCecuring — CBOM](https://www.qcecuring.com/product/cbom)
- [The Quantum Insider — 2026 vendors](https://thequantuminsider.com/2026/03/25/25-companies-building-the-quantum-cryptography-communications-markets/)
- [OWASP CycloneDX — CBOM](https://cyclonedx.org/capabilities/cbom/)
