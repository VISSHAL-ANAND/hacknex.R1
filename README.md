# Evidence-First Cyber Threat Intelligence

**HNX26PSI03 — AI-Powered Cyber Threat Intelligence**

> ### We don't alert because one event looks suspicious. We validate an attack only when independent evidence forms a coherent, entity-consistent and temporally valid chain.

[![Validation](https://img.shields.io/badge/validation-Phases%201--15%20gated-success)](docs/JUDGE_RUNBOOK.md)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](requirements.txt)
[![Backend](https://img.shields.io/badge/backend-FastAPI-009688)](backend/main.py)
[![Security](https://img.shields.io/badge/design-evidence--first-purple)](SOLUTION.md)

---

## 1. What We Built

Security teams receive thousands of events from different sources. The hard problem is not finding *one suspicious event*; it is deciding whether many events actually belong to **one attack**.

Our system reconstructs multi-stage attacks from heterogeneous security telemetry and makes the incident decision **deterministically**.

```
Security Logs
     ↓
Normalization
     ↓
Entity Resolution
     ↓
Behavior Signals
     ↓
Temporal + Entity Correlation
     ↓
Attack-Stage Reasoning
     ↓
Evidence Coverage
     ↓
Deterministic Reconstruction
     ↓
Campaign Confidence
     ↓
┌───────────────────────────────┐
│ Complete coherent chain?      │
└───────────────────────────────┘
      ↓ YES              ↓ NO
VALIDATED INCIDENT   HYPOTHESIS / SILENT
      ↓
Timeline + Evidence + ATT&CK + Response
      ↓
Optional Grounded LLM Investigation
```

### Core rule

**An anomaly is a signal. Evidence proves the incident.**

The system never promotes an isolated anomaly, ATT&CK label, LLM statement, or incomplete chain directly into a validated incident.

---

## 2. The Attack We Demonstrate

Our primary evidence contract covers a removable-media data-exfiltration campaign:

```
Unusual Login
    ↓
New Device / Identity Evidence
    ↓
Sensitive File Access
    ↓
USB / Removable Media
    ↓
Large Copy to Removable Media
    ↓
Deterministic Reconstruction
    ↓
VALIDATED INCIDENT
```

Every mandatory stage must be backed by real event IDs.

If evidence is incomplete:

```
Partial Evidence → Campaign Hypothesis → Analyst Review
```

**Hypothesis ≠ Incident.**

---

## 3. Why This Is Different

### Evidence-first incident gating
Anomaly scores generate candidates; they do not create incidents.

### Incomplete-campaign reasoning
Missing telemetry can produce an explicit hypothesis showing observed stages, missing stages, evidence IDs and confidence without weakening the incident gate.

### Deterministic causal reconstruction
The engine records selected events, rejected decoys, causal relationships, temporal validity and entity consistency.

### Cross-identity protection
IP address alone is never treated as identity. User/device/session continuity is checked across the chain. Ambiguous attribution fails closed instead of stitching unrelated events.

### Bounded temporal drift
We support slow attacks without simply making the global correlation window huge. Extended gaps require stronger identity/session continuity and an ordered stage path.

### LLM as investigator, not judge
The LLM receives a sealed evidence packet **only after deterministic validation**. It explains evidence; it cannot create an incident, invent event IDs or override the detector.

### Adversarial self-validation
The detector is deliberately tested against missing logs, decoys, clock drift, shared identities, simultaneous campaigns, benign lookalikes, reversed input order and large benign haystacks.

---

## 4. What the System Actually Produces

For a validated incident, the dashboard exposes:

- incident status and campaign confidence
- ordered attack timeline
- user/device/IP/resource relationships
- stage-by-stage evidence
- exact evidence event IDs
- deterministic reconstruction
- selected evidence
- rejected/decoy events
- entity conflicts
- temporal validity
- MITRE ATT&CK enrichment
- recommended defensive response actions

The result is an **evidence-backed campaign explanation**, not just an alert score.

---

## 5. Supported Security Telemetry

### Native / canonical
- Windows Security **4624** — logon
- Windows Security **4663** — object/file access
- Windows Event Log XML
- Sysmon **1 / 3 / 11 / 22**
- Zeek **conn / HTTP / DNS**
- Canonical `SecurityEvent` records

### Production-style ingestion layer
The repository also includes:

- JSON / JSONL / CSV / Windows XML / Sysmon / Zeek parsing
- upload size limits
- API event-count limits
- reproducible CLI analysis artifacts
- deterministic WebSocket telemetry replay for the judge demo

---

## 6. AI Boundary

The architecture intentionally separates **decision-making** from **explanation**.

```
Raw Telemetry
    ↓
Deterministic Detection + Reconstruction
    ↓
Validated Incident
    ↓
Sealed Evidence Packet
    ↓
Grounded LLM Investigator
    ↓
Human-readable Investigation
```

The investigator:

- receives only the validated incident evidence packet
- treats telemetry as untrusted data
- must cite real evidence event IDs
- cannot create or validate an incident
- cannot override deterministic confidence
- fails closed when the provider is unavailable
- has no synthetic fallback

The implementation uses a configurable OpenAI-compatible LLM interface through `LLM_BASE_URL`, `LLM_MODEL` and `LLM_API_KEY`. A Gemini-compatible endpoint/model can be used for the demonstrated Gemini investigator; the exact model is supplied by configuration rather than hard-coded into the detector.

---

## 7. MITRE ATT&CK

The project uses a pinned **MITRE ATT&CK Enterprise v19.2** catalog.

Demonstrated mappings include:

| Technique | Meaning |
|---|---|
| **T1078** | Valid Accounts |
| **T1005** | Data from Local System |
| **T1052.001** | Exfiltration Over Physical Medium: USB |

**ATT&CK is enrichment, not evidence.**

A technique label can describe a validated behavior, but it can never create the incident.

---

## 8. Validation — We Attacked Our Own Detector

The project follows:

**BUILD → TEST → BREAK → FIX → REGRESSION → GATE**

### Phase 11 — Adversarial precision/coverage

**26 cases** covering:

- baseline and noisy attacks
- slow attacks
- clock drift
- duplicate events
- missing telemetry
- partial evidence
- decoys
- shared-IP collisions
- cross-entity contamination
- simultaneous campaigns
- two users sharing one device
- identity-stage swaps
- large benign haystacks

Measured gate:

| Metric | Result |
|---|---:|
| Validated-incident precision | **100%** |
| Benign validated FPR | **0%** |
| Campaign coverage recall | **100%** |
| Campaign coverage FPR | **0%** |

### Phase 12 — Confidence + temporal drift

The detector was explicitly tested against slow/long-spacing attacks.

A naive 90-minute global window caused false positives and was rejected. The final implementation uses **bounded adaptive temporal reasoning** with stronger identity/session continuity and ordered-stage validation.

### Phase 13 — Independent Generalization

This benchmark was hardened specifically to avoid overclaiming.

The malicious campaigns are constructed **independently from the demo fixture** rather than cloning or transforming it.

Results:

| Gate | Result |
|---|---:|
| Independently constructed in-contract attacks | **5** |
| Validated in-contract attacks | **5 / 5** |
| Validated recall | **100%** |
| Benign controls | **3** |
| Validated benign FPR | **0%** |
| Out-of-contract network-exfiltration cases | **1** |
| Out-of-contract validated incidents | **0** |

The network-exfiltration case remained non-validated and surfaced only as an incomplete hypothesis.

> **Claim boundary:** 100% refers to the independently constructed synthetic attacks **within the declared removable-media evidence contract**. It is not a claim of 100% recall for arbitrary real-world unseen attacks.

### Phase 14 — Final robustness stress

The final stress gate includes:

- **20,000 benign events + a real attack**
- **20,000 benign events only**
- duplicate attack events
- reversed input order
- clean controls

The final robustness gate passed.

### Phase 15 — Final release gate

Phase 15 combines:

- targeted adversarial/generalization/robustness tests
- full `pytest` regression
- frontend JavaScript syntax validation
- release-contract checks

Behavioral validation is primarily established by **Phases 11–14**; Phase 15 verifies that those gates and the repository release contract remain intact.

---

## 9. Public Dataset Validation

### Splunk Attack Data

The public validation track processed **6,208 security telemetry records** with:

- **0 parse errors**
- **0 normalization errors**

The purpose is heterogeneous-log compatibility and normalization validation, not a claim of universal attack recall.

### CERT Insider Threat Test Dataset r4.2

The raw benchmark used externally acquired raw:

- `logon.csv`
- `device.csv`
- `file.csv`
- `insiders.csv`

Verified row counts:

| File | Rows |
|---|---:|
| `logon.csv` | **854,859** |
| `device.csv` | **405,380** |
| `file.csv` | **445,581** |
| `insiders.csv` | **191** |
| Malicious answer-key scenarios | **70** |

The project-compatible evidence contract matched **3 / 70** malicious scenarios.

**4.29% is compatibility coverage, NOT detector recall.**

All 3 compatible scenarios completed the ordered project evidence chain.

The raw CERT workflow is intentionally separate because the raw corpus and official answer-key data are acquired externally and are not committed to the repository.

See:

- `docs/CERT_RAW_ACQUISITION.md`
- `docs/PHASE8_CERT_RAW_GATE.md`
- `backend/cert_raw_benchmark.py`

---

## 10. False-Positive Philosophy

The detector is designed to prefer **uncertainty over fabricated certainty**.

Examples:

| Situation | Result |
|---|---|
| Complete coherent attack | **Validated incident** |
| Missing mandatory evidence | **Campaign hypothesis** |
| Contradictory identity | **Suppressed / fail closed** |
| Shared IP only | **Not enough for identity** |
| Shared device + conflicting users | **Fail closed** |
| Authorized transfer | **Suppressed** |
| Reversed causal order | **Suppressed** |
| Unsupported network-exfiltration modality | **Not validated** |

This is deliberate: a cybersecurity system should not manufacture an accusation from ambiguous telemetry.

---

## 11. Project Structure

```
hacknex.R1/
├── backend/
│   ├── main.py                 # FastAPI API + upload + live replay
│   ├── models.py               # Canonical data models
│   ├── detector.py             # Deterministic incident gate
│   ├── reconstructor.py        # Causal reconstruction
│   ├── investigator.py         # Grounded LLM boundary
│   ├── adapters.py             # Windows / Sysmon / Zeek adapters
│   ├── normalizer.py           # Raw event normalization
│   ├── behavior.py             # Behavioral context
│   ├── attack_intel.py         # ATT&CK enrichment
│   ├── cert_raw_benchmark.py   # Raw CERT benchmark
│   └── data/                   # Controlled demo scenarios
│
├── frontend/
│   ├── index.html              # Security console
│   ├── app.js                  # Dashboard + live replay
│   └── style.css               # Console UI
│
├── tests/
│   ├── phase tests             # Phase 2–15 gates
│   └── regression tests        # Detector/API/security regression
│
├── docs/
│   ├── JUDGE_RUNBOOK.md
│   ├── PHASE8_CERT_RAW_GATE.md
│   ├── PHASE13_GENERALIZATION.md
│   ├── PHASE14_FINAL_ROBUSTNESS.md
│   └── PRESENTATION.md
│
├── scripts/
│   ├── run_cert_raw_benchmark.py
│   └── verify_cert_raw_layout.py
│
└── .github/workflows/
    └── phase2.yml ... phase15.yml
```

---

## 12. Quick Start

### Requirements

- Python **3.10+**
- Node.js for frontend syntax validation
- Git

### Install

```bash
git clone https://github.com/VISSHAL-ANAND/hacknex.R1.git
cd hacknex.R1

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### Run

```bash
uvicorn backend.main:app --reload
```

Open:

```
http://127.0.0.1:8000
```

### Health check

```bash
curl http://127.0.0.1:8000/health
```

Expected:

```json
{"status":"ok","service":"evidence-first-cti"}
```

---

## 13. Main API Surface

| Endpoint | Purpose |
|---|---|
| `GET /health` | Service health |
| `GET /api/scenarios` | Available demo scenarios |
| `GET /api/demo/{scenario}` | Analyze a controlled scenario |
| `GET /api/demo/attack` | Full attack demo |
| `GET /api/demo/clean` | Clean-control demo |
| `POST /api/analyze` | Analyze canonical SecurityEvent records |
| `POST /api/analyze/upload` | Analyze JSON/JSONL/CSV/XML uploads |
| `POST /api/analyze/raw` | Normalize + analyze raw events |
| `POST /api/analyze/windows` | Windows event adapter |
| `POST /api/analyze/windows/xml` | Windows XML adapter |
| `POST /api/analyze/sysmon` | Sysmon adapter |
| `POST /api/analyze/zeek` | Zeek adapter |
| `POST /api/reconstruct` | Deterministic reconstruction |
| `POST /api/investigate` | Grounded investigation of a validated incident |
| `GET /api/phase2/report` | Phase 2 validation report |
| `WS /ws/simulate/{scenario}` | Deterministic live telemetry replay |

The upload and API paths enforce configurable event/byte limits to avoid unbounded ingestion.

---

## 14. Validation Commands

Run the complete regression suite:

```bash
python -m pytest -q
```

Run the major judge-facing gates:

```bash
python -m pytest -q tests/test_phase11_adversarial_benchmark.py
python -m pytest -q tests/test_phase12_confidence_drift.py
python -m pytest -q tests/test_phase13_generalization_benchmark.py
python -m pytest -q tests/test_phase14_final_robustness.py
python -m pytest -q tests/test_phase15_final_release.py
node --check frontend/app.js
```

---

## 15. Judge Demo

The recommended order is:

1. **Run Judge Demo** → show **VALIDATED INCIDENT**
2. Open the timeline → show the causal sequence
3. Open stage evidence → show exact event IDs
4. Open reconstruction → show selected vs rejected decoys
5. Show ATT&CK → explain that it is enrichment
6. Show the grounded AI investigator → explain that AI is downstream of validation
7. **Run Clean** → show **SUPPRESSED**
8. Run `partial_attack` → show **hypothesis, not incident**
9. Run `mismatched_entities` → show **suppression**
10. Run `authorized_transfer` → show **suppression**

Full presentation material:

- `PRESENTATION.md`
- `docs/JUDGE_RUNBOOK.md`
- `SOLUTION.md`

---

## 16. Security Design Principles

1. **Evidence first, explanation second.**
2. Logs are **untrusted data**, never instructions.
3. Anomaly scores cannot directly create incidents.
4. ATT&CK cannot create incidents.
5. LLM output cannot create or validate incidents.
6. Every validated stage requires real evidence IDs.
7. IP address alone is not identity.
8. Cross-user/device conflicts fail closed.
9. Missing evidence does not lower the incident gate.
10. Unsupported attack modalities are not falsely claimed as detected.
11. Large/untrusted inputs are bounded.
12. Grounded investigation uses a sealed evidence packet and deterministic citation validation.

---

## 17. Limitations — Stated Honestly

The current prototype does **not** claim universal threat detection.

Current scope is strongest for the declared removable-media evidence contract and its tested telemetry patterns.

Important limitations:

- unsupported attack modalities may remain hypotheses or silent
- public datasets do not represent every enterprise environment
- identity attribution can remain ambiguous when telemetry lacks session-level context
- production deployment would require streaming storage, durable state, access control, tenant isolation, secrets management and operational monitoring
- benchmark results are controlled measurements, not guarantees of production prevalence-weighted performance

These limitations are explicit by design rather than hidden behind a broad accuracy claim.

---

## 18. Documentation

| Document | Purpose |
|---|---|
| `SOLUTION.md` | Full technical solution |
| `PRESENTATION.md` | Judge-facing 9-slide presentation |
| `docs/JUDGE_RUNBOOK.md` | Exact demo flow + Q&A |
| `docs/PHASE13_GENERALIZATION.md` | Independent generalization methodology |
| `docs/PHASE14_FINAL_ROBUSTNESS.md` | Final stress methodology |
| `docs/PHASE8_CERT_RAW_GATE.md` | Raw CERT gate |
| `docs/CERT_RAW_ACQUISITION.md` | Raw CERT acquisition/provenance |

---

## 19. Final Status

| Phase | Scope | Status |
|---|---|---|
| 1 | Core evidence-first detection | ✅ |
| 2 | False-positive battle | ✅ |
| 3 | Heterogeneous log adapters | ✅ |
| 4 | Behavioral baseline | ✅ |
| 5 | ATT&CK intelligence | ✅ |
| 6 | Deterministic reconstruction | ✅ |
| 7 | Grounded LLM investigator | ✅ |
| 8 | Public + raw CERT validation | ✅ |
| 9 | Judge demo hardening | ✅ |
| 10 | Evidence coverage / hypotheses | ✅ |
| 11 | Adversarial benchmark | ✅ |
| 12 | Confidence + drift robustness | ✅ |
| 13 | Independent generalization | ✅ |
| 14 | Final robustness stress | ✅ |
| 15 | Final release gate | ✅ |

**Release principle:**

> ### Evidence first. Explanation second.

**We are not building another alert generator. We are building a system that can show why an incident is actually proven — and when the evidence is insufficient, it refuses to pretend otherwise.**
