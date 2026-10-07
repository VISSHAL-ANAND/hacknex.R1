# Evidence-First Cyber Threat Intelligence

**HNX26PSI03 — AI-Powered Cyber Threat Intelligence**

An explainable cyber threat-intelligence engine that reconstructs multi-stage attacks from heterogeneous security telemetry. The system does **not** turn a single anomaly into an incident. It correlates evidence across identity, device, file and removable-media activity, validates temporal/entity consistency, reconstructs the causal chain, and only then produces a validated incident.

> **Evidence first, explanation second.**
>
> An anomaly is not an incident. A validated incident requires a coherent, evidence-backed attack chain.

## 1. What the project does

The system processes security telemetry through:

```
Security Logs
  ↓
Event Normalization
  ↓
Entity Resolution
  ↓
Behavior Signals
  ↓
Temporal + Entity Correlation
  ↓
Attack-Stage Reasoner
  ↓
Evidence Coverage
  ↓
Campaign Confidence
  ↓
Validated Incident / Campaign Hypothesis / Silent
  ↓
Timeline + Evidence + Reconstruction + ATT&CK + Response
  ↓
Optional Grounded LLM Investigation
```

The mandatory attack contract requires evidence for:

1. **Initial Access / Identity Anomaly**
2. **Sensitive Data Access**
3. **Collection / Exfiltration**

For the removable-media exfiltration path, the detector requires a file copy of at least 1 GB with USB/removable-media evidence.

### Detection boundaries

| Signal | Meaning | Can create a validated incident? |
|---|---|---:|
| Event anomaly | One event looks unusual | No |
| Behavioral signal | Activity differs from baseline | No |
| Campaign hypothesis | Compatible evidence is incomplete | No |
| ATT&CK mapping | Threat-intelligence enrichment | No |
| Deterministic reconstruction | Evidence forms a valid causal chain | Required |
| Validated incident | Complete, temporally valid, entity-consistent chain | **Yes** |
| LLM investigation | Explanation of a validated incident | No |

Incomplete evidence can become a **CampaignHypothesis** for analyst review, but cannot bypass the incident gate.

## 2. Demonstrated attack

```
Unusual Login
      ↓
New Device
      ↓
Sensitive File Access
      ↓
USB / Removable Media
      ↓
Large Copy to USB
      ↓
Deterministic Reconstruction
      ↓
Validated Incident
```

The repository also contains benign and adversarial scenarios including clean activity, partial chains, reversed ordering, slow attacks, mismatched entities, authorized transfers, benign backups, shared-IP collisions, cross-user/device contamination, noisy attacks, decoy-heavy attacks, large benign haystacks and simultaneous campaigns.

## 3. Technologies, libraries and models

### Core stack

- **Python 3.10+**
- **FastAPI** — REST API/application server
- **Uvicorn** — ASGI server
- **Pydantic 2** — canonical security-event and response models
- **Pytest** — automated testing/regression
- **HTML / CSS / JavaScript** — judge dashboard
- **GitHub Actions** — CI gates

### Security telemetry

Supported adapters:

- Windows Security **4624 / 4663**
- Windows XML
- Sysmon **1 / 3 / 11 / 22**
- Zeek **conn / HTTP / DNS**
- Canonical `SecurityEvent`

### Threat intelligence

- **MITRE ATT&CK Enterprise v19.2**
- Demonstrated mappings:
  - **T1078 — Valid Accounts**
  - **T1005 — Data from Local System**
  - **T1052.001 — Exfiltration over USB**

ATT&CK is enrichment only; it cannot create or validate an incident.

### AI / LLM

The core detector is deterministic and requires **no ML model or LLM**.

The optional investigator uses an **OpenAI-compatible HTTP API** after deterministic incident validation. It uses temperature 0, structured JSON, exact event-ID grounding, deterministic grounding validation and no synthetic fallback.

### Pinned dependencies

```text
fastapi==0.117.1
uvicorn[standard]==0.37.0
pydantic==2.11.9
pytest==8.4.2
```

No external model download is required for the deterministic demo.

## 4. Repository structure

```
backend/
  main.py                  # FastAPI application/API
  models.py                # Pydantic models
  detector.py              # deterministic detection/correlation
  reconstructor.py         # causal reconstruction
  normalizer.py            # generic normalization
  adapters.py              # Windows/Sysmon/Zeek adapters
  behavior.py              # behavioral baseline/signals
  attack_intel.py          # ATT&CK enrichment
  investigator.py          # optional grounded LLM investigator
  evaluator.py             # scenario evaluator
  cert_raw_benchmark.py    # raw CERT benchmark
  data/
    scenarios.json         # demo/adversarial scenarios
    attack_logs.json
    clean_logs.json
    attack_intelligence.json

frontend/
  index.html
  app.js
  style.css

scripts/
  run_cert_raw_benchmark.py
  verify_cert_raw_layout.py

tests/
  test_phase9_judge_demo.py
  test_phase10_evidence_coverage.py
  test_phase11_adversarial_benchmark.py
  test_phase12_confidence_drift.py
  test_phase13_generalization_benchmark.py
  test_phase14_final_robustness.py
  test_phase15_final_release.py

docs/
  JUDGE_RUNBOOK.md
  CERT_RAW_ACQUISITION.md
  PHASE8_CERT_RAW_GATE.md
  PHASE13_GENERALIZATION.md
  PHASE14_FINAL_ROBUSTNESS.md

.github/workflows/
  phase2.yml ... phase15.yml
  phase8-cert-raw.yml

requirements.txt
README.md
```

## 5. Installation

### Prerequisites

- Python **3.10+**
- Git
- Modern web browser
- Node.js only for the frontend syntax check

Clone:

```bash
git clone https://github.com/VISSHAL-ANAND/hacknex.R1.git
cd hacknex.R1
```

Create a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Linux/macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 6. Configuration

### Normal deterministic demo

No environment variables are required.

Start the application:

```bash
uvicorn backend.main:app --reload
```

Open:

```
http://127.0.0.1:8000
```

### Optional grounded LLM investigator

Configure an OpenAI-compatible provider only if LLM investigation is required.

**Windows PowerShell:**

```powershell
$env:LLM_BASE_URL="https://your-provider.example/v1/chat/completions"
$env:LLM_MODEL="your-model"
$env:LLM_API_KEY="your-api-key"
$env:LLM_PROVIDER="openai-compatible"
$env:LLM_TIMEOUT="30"
```

**Linux/macOS:**

```bash
export LLM_BASE_URL="https://your-provider.example/v1/chat/completions"
export LLM_MODEL="your-model"
export LLM_API_KEY="your-api-key"
export LLM_PROVIDER="openai-compatible"
export LLM_TIMEOUT="30"
```

Never commit API keys. If `LLM_BASE_URL` or `LLM_MODEL` is missing, investigation fails closed.

## 7. Run the system

Start:

```bash
uvicorn backend.main:app --reload
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Expected:

```json
{"status":"ok","service":"evidence-first-cti"}
```

Open the dashboard at `http://127.0.0.1:8000`.

## 8. API

### Demo

```text
GET /api/scenarios
GET /api/demo/{scenario}
GET /api/demo/attack
GET /api/demo/clean
```

Examples:

```bash
curl http://127.0.0.1:8000/api/demo/full_attack
curl http://127.0.0.1:8000/api/demo/clean
```

### Analysis

```text
POST /api/analyze
POST /api/analyze/raw
POST /api/analyze/windows
POST /api/analyze/windows/xml
POST /api/analyze/sysmon
POST /api/analyze/zeek
POST /api/analyze/behavior
```

### Reconstruction/investigation

```text
POST /api/reconstruct
POST /api/investigate
```

### Validation

```text
GET /api/phase2/report
GET /api/incidents
```

## 9. How to reproduce the demonstrated results

### A. Reproduce the full attack

Start the server:

```bash
uvicorn backend.main:app --reload
```

Then:

```bash
curl http://127.0.0.1:8000/api/demo/full_attack
```

Expected:

- one validated incident
- three mandatory stages
- evidence event IDs
- deterministic reconstruction
- causal timeline
- entity graph
- ATT&CK enrichment
- response recommendations

The exact demo evidence is stored in `backend/data/scenarios.json`.

### B. Reproduce benign suppression

```bash
curl http://127.0.0.1:8000/api/demo/clean
```

Expected:

- zero validated incidents
- suppressed/no incident
- no causal attack reconstruction

### C. Reproduce adversarial controls

```bash
curl http://127.0.0.1:8000/api/demo/login_only
curl http://127.0.0.1:8000/api/demo/usb_only
curl http://127.0.0.1:8000/api/demo/reversed_order
curl http://127.0.0.1:8000/api/demo/slow_attack
curl http://127.0.0.1:8000/api/demo/mismatched_entities
curl http://127.0.0.1:8000/api/demo/authorized_transfer
curl http://127.0.0.1:8000/api/demo/benign_backup
```

These controls must not become validated incidents.

### D. Reproduce the complete test gate

```bash
python -m pytest -q
```

Frontend syntax:

```bash
node --check frontend/app.js
```

Phase-specific checks:

```bash
python -m pytest -q tests/test_phase11_adversarial_benchmark.py
python -m pytest -q tests/test_phase12_confidence_drift.py
python -m pytest -q tests/test_phase13_generalization_benchmark.py
python -m pytest -q tests/test_phase14_final_robustness.py
python -m pytest -q tests/test_phase15_final_release.py
```

### E. Reproduce the judge presentation

Use `docs/JUDGE_RUNBOOK.md`.

Recommended order:

```
Full Attack
  → show exact evidence
  → show deterministic reconstruction
  → show ATT&CK enrichment
  → Run Clean
  → show suppression
  → run partial/entity/authorization adversarial cases
  → explain evidence-first novelty
```

## 10. Benchmark and validation results

### Phase 2 — False-positive battle

13 controlled scenarios:

- **0 false positives**
- **0 missed validated attacks**
- all expected dispositions passed

### Phase 8 — Raw CERT r4.2

The raw CERT benchmark was executed using raw logon, device and file data plus official answer-key information.

| File | Rows |
|---|---:|
| logon.csv | 854,859 |
| device.csv | 405,380 |
| file.csv | 445,581 |
| insiders.csv | 191 |
| malicious scenarios | 70 |

| Metric | Result |
|---|---:|
| Project-compatible scenarios | 3 / 70 |
| Compatibility rate | **4.29%** |
| Identity-stage proxy recall | **100.00%** |
| Sensitive-stage proxy recall | **5.71%** |
| Exfil-stage proxy recall | **4.29%** |
| Ordered-chain proxy recall | **4.29%** |
| Compatible ordered-chain recall | **100.00%** |
| Benign windows sampled | 300 |
| Benign proxy chains | 7 |
| Benign proxy-chain rate | **2.33%** |

**Important:** 4.29% is a project/dataset compatibility rate, **not** end-to-end detector recall over all 70 malicious scenarios. Only 3 scenarios matched the project's current identity → sensitive-file → removable-media evidence contract.

### Phase 11 — Adversarial benchmark

Final benchmark: **26 cases**.

Coverage includes noisy/slow attacks, clock drift, interleaving, duplicate events, cross-user decoys, large benign haystacks, cross-entity contamination, simultaneous campaigns, shared-device/two-user cases and identity-stage swaps.

Measured gate:

| Metric | Result |
|---|---:|
| Cases | 26 |
| Validated malicious cases | 8 |
| Benign validated false positives | 0 |
| Validated-incident precision | **100%** |
| Campaign coverage recall | **100%** |
| Campaign coverage FPR | **0%** |

The benchmark distinguishes validated-incident recall from campaign coverage so incomplete evidence is not incorrectly treated as a missed complete attack.

### Phase 12 — Confidence/drift

Tested against baseline, clock drift, long spacing, noisy long spacing, ambiguous partial evidence and benign controls.

A naive global 90-minute correlation window was rejected because it caused false positives. The final design uses bounded adaptive correlation with stronger identity/session continuity and ordered stage-path validation.

### Phase 13 — Generalization

Unseen/transformed cases covered rotated attack structures, interleaved benign activity, decoy-heavy attacks, missing telemetry, simultaneous campaigns, benign lookalikes and large haystacks.

Verified gate:

- malicious validated recall: **100%**
- benign validated FPR: **0%**

### Phase 14 — Final robustness

Stress tests included:

- 20,000 benign events + real attack
- 20,000 benign events only
- duplicate attack events
- reversed input order
- baseline replay
- benign backup

The final robustness workflow passed.

### Phase 15 — Final release gate

The final release gate verifies:

- required implementation files
- benchmark/test files
- documentation
- workflow files
- README release markers
- targeted Phase 11–15 tests
- full Pytest regression
- frontend JavaScript syntax

The release gate passed before final judge-readiness documentation was merged.

## 11. Raw CERT reproduction

Raw CERT data is intentionally not committed because of its size.

Expected layout:

```
external/cert_raw/
├── logon.csv
├── device.csv
├── file.csv
└── insiders.csv
```

Validate:

```bash
python scripts/verify_cert_raw_layout.py
```

Run:

```bash
python scripts/run_cert_raw_benchmark.py
```

Acquisition/provenance:

- `docs/CERT_RAW_ACQUISITION.md`
- `docs/PHASE8_CERT_RAW_GATE.md`

## 12. CI / automated validation

GitHub Actions provides phase-specific gates:

```text
Phase 2  → false-positive validation
Phase 3  → heterogeneous telemetry
Phase 4  → behavior
Phase 5  → ATT&CK
Phase 6  → reconstruction
Phase 7  → grounded investigator
Phase 8  → public/raw-data validation
Phase 9  → judge demo
Phase 10 → evidence coverage
Phase 11 → adversarial benchmark
Phase 12 → confidence/drift
Phase 13 → generalization
Phase 14 → final robustness
Phase 15 → release contract
```

The expensive raw CERT gate is intentionally separate from ordinary CI and is triggered independently.

## 13. Security and evaluation constraints

The project intentionally avoids:

- anomaly-only incident generation
- ATT&CK-only detection
- LLM-generated incidents
- fabricated benchmark results
- presenting synthetic data as real-data validation
- unsupported evidence IDs
- cross-user entity stitching
- temporally impossible attack chains
- unrestricted correlation windows
- automatic retraining during evaluation

Logs are treated as **untrusted data**, never as instructions.

## 14. Judge runbook

See:

```text
docs/JUDGE_RUNBOOK.md
```

One-line pitch:

> **We don't alert because one event looks suspicious; we validate an attack only when independent evidence forms a coherent, entity-consistent, temporally valid chain — and we show the exact events that prove it.**

## 15. Project status

| Phase | Scope | Status |
|---|---|---|
| 1 | Core detection | ✅ Complete |
| 2 | False-positive benchmark | ✅ Complete |
| 3 | Heterogeneous log adapters | ✅ Complete |
| 4 | Behavioral baseline | ✅ Complete |
| 5 | MITRE ATT&CK intelligence | ✅ Complete |
| 6 | Deterministic reconstruction | ✅ Complete |
| 7 | Grounded LLM investigator | ✅ Complete |
| 8 | Public + raw CERT validation | ✅ Complete |
| 9 | Judge demo + CI hardening | ✅ Complete |
| 10 | Evidence-coverage hardening | ✅ Complete |
| 11 | Adversarial precision/coverage | ✅ Complete |
| 12 | Confidence + drift robustness | ✅ Complete |
| 13 | Generalization benchmark | ✅ Complete |
| 14 | Final robustness | ✅ Complete |
| 15 | Final release gate | ✅ Complete |

**Current state: release-ready engineering baseline with deterministic evidence-first incident validation.**

**Evidence first, explanation second.**
