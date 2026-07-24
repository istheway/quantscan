# QuantScan

**Post-quantum cryptography readiness auditor.**

QuantScan discovers the cryptography in your code and infrastructure,
classifies every asset by its resistance to a cryptographically-relevant quantum
computer (CRQC), and produces an auditor-ready migration report. Each finding is
mapped to its **NIST IR 8547** migration action and **CNSA 2.0** deadline, with
cross-referenced control frameworks (PCI DSS 4.0, SOC 2, ISO 27001).

It runs as a single pipeline:

```
discover ─▶ merge ─▶ ingest ─▶ classify ─▶ score ─▶ comply ─▶ report
(CBOMkit)   (dedup)  (CycloneDX) (CRQC risk) (0–100) (guidance) (HTML·PDF·JSON)
```

## Why

*Harvest-now-decrypt-later*: data encrypted with quantum-vulnerable algorithms
today can be captured now and broken once a CRQC exists. Standards bodies have
set concrete PQC migration deadlines. QuantScan turns a cryptographic scan
into evidence — *what* cryptography you run, *how exposed* it is, and *what you
must change by when*.

## Capabilities

### 1. Discover — build a CBOM from code and infrastructure

`quantscan discover` builds a CycloneDX 1.6 CBOM from the
[CBOMkit](https://github.com/PQCA/cbomkit) toolchain — the `cbomkit-theia`
scanner is **vendored and runs in-process** (no external binary), while
source-code analysis is fetched from a CBOMkit service. Three input sources,
each a repeatable flag:

| Source | Backend | Detects |
|--------|---------|---------|
| `--dir <path>` | embedded cbomkit-theia | Certificates, keys, and OpenSSL/TLS config in a source tree or filesystem |
| `--image <ref>` | embedded cbomkit-theia | The same, inside a container/OCI image (via the Docker daemon) |
| `--purl <purl>` | CBOMkit service (HTTP) | Source-code crypto **API usage** (Sonar Cryptography static analysis) |

`--dir`/`--image` cover crypto *artifacts* (cert/key/config files); actual
source-code algorithm *calls* come from the CBOMkit service via `--purl`
(`--cbomkit-url`). You can combine all three in one run.

**Merge with reference integrity.** The same asset is often reported by more than
one scanner (or the same CA cert appears in several files). Merge collapses
duplicates — first by `bom-ref`, then by identity `assetType|name|parameters` —
and unions their evidence locations so no provenance is lost. Crucially, when a
duplicate is dropped, any reference to it (such as a certificate's
`subjectPublicKeyRef`) is **rewritten** to the surviving asset, so downstream
resolution never dangles.

### 2. Ingest & normalize

The `cbom` package parses a CycloneDX 1.6 document and flattens each
`cryptographic-asset` component into a normalized model: family, primitive,
parameters (parameter-set / curve / key length), source locations, classical and
NIST quantum security levels, and certificate subject / issuer / expiry.

- **Family normalization** is deliberately forgiving of how CBOM producers spell
  things: `Kyber` → `ML-KEM`, `Dilithium` → `ML-DSA`, `SPHINCS+` → `SLH-DSA`,
  `Falcon` → `FN-DSA`, `ECDSA`/`ECDH`/`Ed25519`/`X25519` → `ECC`, `3DES` → `DES`,
  and so on — so assets classify consistently regardless of source.
- **Certificate resolution.** A certificate's name is its subject (a CA name),
  which carries no algorithm. QuantScan resolves each certificate's
  cryptography from the components it references — the **subject public key**
  first, then the **signature algorithm** — so a trust store full of RSA/ECDSA
  certs is correctly flagged instead of landing in "Unknown".

### 3. Classify quantum risk

Every asset is placed in one of four classes, using deterministic, table-driven
rules (reproducible across scans — a hard requirement for audit artifacts):

| Class | Meaning | Examples |
|-------|---------|----------|
| **Quantum-broken** | Broken by Shor's algorithm on a CRQC, regardless of key size | RSA, ECC, DH, DSA |
| **Quantum-weakened** | Grover-weakened or already deprecated | AES-128, SHA-256, SHA-1, MD5, DES |
| **Quantum-ready** | PQC, or resistant at standardized parameters | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384+, ChaCha20 |
| **Unknown** | Family not recognized; manual review required | — |

The size-sensitive families are judged on their parameters: **AES** is ready at
256-bit and weakened at 128-bit; **SHA/SHA-3** is ready with a ≥384-bit digest
and weakened below it. Each verdict carries a plain-English rationale.

### 4. Score readiness

Per-asset classes roll up into an org-level **quantum-readiness score** (0–100).
Broken assets carry the heaviest penalty, then weakened, then unknown; ready
assets are free. The score maps to a risk label:

| Score | Risk label |
|-------|-----------|
| 90–100 | Low |
| 70–89 | Moderate |
| 40–69 | Elevated |
| 0–39 | Critical |

Findings are ordered worst-first, so the report leads with the highest-risk assets.

### 5. Map to compliance guidance

Each crypto family is mapped to actionable, standards-aligned guidance:

- a **NIST IR 8547** migration action (what to replace it with),
- a **CNSA 2.0** deadline (by when), and
- cross-referenced **control frameworks** — PCI DSS 4.0, SOC 2, ISO 27001.

This is what turns a raw inventory into audit evidence: for every asset, what
must change and by when.

### 6. Render reports

`scan -f` produces the audit output in three shapes:

| Format | Description |
|--------|-------------|
| `html` | Standalone, branded, print-ready report (single embedded template) |
| `pdf` | The same rendered to A4 PDF via headless Chrome |
| `json` | Machine-readable summary: score, class counts, and per-asset verdicts with guidance |

The report opens with a scored executive summary (a risk-colored gauge and
class-count cards), then a **cryptographic inventory & migration roadmap** table
(asset, family, classification, required action, CNSA 2.0 deadline, evidence
location), and a **control-framework cross-reference**. `--org` brands the cover.

## Requirements

- **Go 1.26+** (see [`go.mod`](go.mod)) to build from source. Linux, macOS, or
  Windows on `amd64` / `arm64`.
- **Optional external services**, each only needed for the feature that uses it:

| Feature | Requirement |
|---------|-------------|
| `scan -f pdf` | A Chromium/Chrome binary on `PATH` (auto-detected; override with `--chrome`) |
| `discover --image` | A running Docker daemon (to pull/extract the image) |
| `discover --purl` | A running [CBOMkit](https://github.com/PQCA/cbomkit) service (`--cbomkit-url`) |

The filesystem scanner ([`cbomkit-theia`](https://github.com/cbomkit/cbomkit-theia))
is **vendored and runs in-process** — no separate binary to install. The core
`scan` command needs nothing external for HTML/JSON output.

## Install

```sh
go build -o quantscan ./cmd/quantscan
```

A single self-contained binary — `discover --dir` and `--image` work out of the
box (`--image` additionally talks to your Docker daemon).

## Quick start

```sh
# Discover crypto in the current tree and save it to ./cbom-<timestamp>.json
quantscan discover --dir .

# Or stream discovery straight into a branded PDF in one shot.
# (discover -o - writes to stdout; scan's trailing "-" reads stdin.)
quantscan discover --dir . -o - | quantscan scan -f pdf --org "Acme Corp" -o report.pdf -
```

Already have a CBOM? Skip discovery and score it directly:

```sh
quantscan scan cbom.json -f pdf --org "Acme Corp" -o report.pdf
```

## Command reference

Global flags work on any command: `-h, --help` prints usage, and `-v, --version`
(e.g. `quantscan --version`) reports the build version.

### `discover`

```sh
quantscan discover [flags]
```

| Flag | Description |
|------|-------------|
| `--dir <path>` | Scan a directory (source tree / filesystem) with the embedded cbomkit-theia. Repeatable. |
| `--image <ref>` | Scan a container/OCI image (via Docker). Repeatable. |
| `--purl <purl>` | Fetch a source-code CBOM from a CBOMkit service (needs `--cbomkit-url`). Repeatable. |
| `--cbomkit-url <url>` | Base URL of a running CBOMkit service, e.g. `http://localhost:8081`. |
| `--ignore <glob>` | Glob excluded from the filesystem scan. Repeatable. |
| `--max-file-size <size>` | Skip files larger than this during `--dir`/`--image` scans, e.g. `512KB`, `10MB` (default: `1MB`). |
| `--skip-plugins <names>` | Comma-separated cbomkit-theia plugins to skip during `--dir`/`--image` scans. Choices: `certificates`, `javasecurity`, `secrets`, `opensslconf`, `problematicca`. E.g. `--skip-plugins secrets`. |
| `--out-dir <dir>` | Directory for the auto-named `cbom-<timestamp>.json` (default: current directory; created if missing). |
| `-o, --out <file>` | Explicit output file, or `-` for stdout (overrides `--out-dir`). |

By default the merged CBOM is saved to `cbom-<YYYYMMDD-HHMMSS>.json` (e.g.
`cbom-20260704-143022.json`) in the current directory, so every run leaves a
timestamped audit artifact. Use `--out-dir` to collect them elsewhere, `-o <file>`
for a fixed name, or `-o -` to stream to stdout.

```sh
# Save to ./cbom-<timestamp>.json (default)
quantscan discover --dir . --image myapp:latest

# Collect timestamped CBOMs in a directory
quantscan discover --dir . --out-dir ./cboms

# Explicit filename, plus a source-code scan from a CBOMkit service
quantscan discover --dir . --cbomkit-url http://localhost:8081 \
  --purl pkg:github/myorg/myapp -o cbom.json

# Scan a directory but skip theia's secret detector
quantscan discover --dir . --skip-plugins secrets
```

`--ignore`, `--max-file-size`, and `--skip-plugins` tune the in-process
cbomkit-theia scan (`--dir`/`--image`) only; they have no effect on `--purl`,
which is analyzed server-side by the CBOMkit service.

### `scan`

```sh
quantscan scan <cbom.json | -> [flags]
```

Pass `-` as the path to read the CBOM from stdin (e.g. piped from `discover`).

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --format` | Output format: `html`, `pdf`, or `json` | `html` |
| `-o, --out` | Output file, or `-` for stdout | `report-<timestamp>.<format>` beside the CBOM |
| `--org` | Organization name for the report cover | `Client Organization` |
| `--chrome` | Path to the Chromium binary for PDF | auto-detect |
| `--fail-under N` | Exit non-zero if the readiness score is below `N` (gate for pipelines) | off |

By default the report is saved next to the input CBOM as
`report-<YYYYMMDD-HHMMSS>.<format>` (e.g. `report-20260704-143022.pdf`); when the
CBOM is read from stdin it lands in the current directory. Use `-o <file>` for a
fixed name or `-o -` to stream to stdout.

```sh
# Save a branded PDF beside the CBOM as report-<timestamp>.pdf (default)
quantscan scan cbom.json -f pdf --org "Acme Corp"

# Machine-readable summary to stdout
quantscan scan cbom.json -f json -o -

# Gate: exit non-zero if readiness drops below 80
quantscan scan cbom.json -f json --fail-under 80 -o -
```

## Architecture

Data flows one way through small, single-purpose packages. The `cbomkit-theia`
scanner is vendored and invoked **in-process** (no external binary), and the
optional CBOMkit service is reached over HTTP; because everything speaks
CycloneDX 1.6, `discover` is a merge layer feeding the scoring pipeline rather
than a second parser.

```
discover ─▶ Merge ─▶ cbom.Load ─▶ scoring.Score ─▶ compliance ─▶ report
(theia +    (dedup)  (normalize)   (classify)       (guidance)    (render)
 CBOMkit)
```

Vendoring theia makes QuantScan a single self-contained binary for filesystem and
image scanning, at the cost of a larger dependency tree (docker, viper, gitleaks)
and binary (~41 MB). The CBOMkit service stays external — it is a Java/Quarkus
application and cannot be embedded in a Go binary.

```
cmd/quantscan/          CLI (cobra): the discover and scan commands, flag wiring,
                       the JSON projection, and version reporting
internal/discover/     Build a CBOM from code + infrastructure
  discover.go            Scanner interface + Merge (dedup assets, rewrite refs)
  theia.go               TheiaScanner: runs vendored cbomkit-theia in-process (dir/image)
  cbomkit.go             CBOMkitClient: fetches source-code CBOMs over REST
internal/cbom/         Ingest a CycloneDX 1.6 CBOM → normalized Asset model,
                       family normalization, certificate reference resolution
internal/scoring/      Classify quantum risk and compute the 0–100 rollup score
internal/compliance/   Map families → NIST IR 8547 / CNSA 2.0 guidance + controls
internal/report/       Render HTML (embedded template) and PDF (headless Chrome)
```

## Scope & disclaimer

Findings derive from an automated CBOM scan and support SOC 2 / HIPAA / PCI DSS
evidence collection. This artifact does not constitute a formal attestation.
CNSA 2.0 dates reflect published guidance as of mid-2026 and are centralized in
`internal/compliance` for review as standards evolve.

## License

QuantScan is released under the [MIT License](LICENSE) — free to use, modify,
and redistribute, including commercially.

It statically links third-party open-source Go modules, each under its own
permissive license (MIT, Apache-2.0, BSD, MPL-2.0, ISC, CC0). Their full
license texts and required attributions are reproduced in
[`THIRD_PARTY_NOTICES.txt`](THIRD_PARTY_NOTICES.txt), which ships with every
release archive.
