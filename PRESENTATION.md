# PRESENTATION — SIH 2026
## HNX26PSI03 — AI-Powered Cyber Threat Intelligence

> **8 SIH-style presentation slides + 1 Business Model Canvas slide**
>
> **Core message:** Evidence first, explanation second.

This document is the **slide-by-slide master content** for the final SIH presentation. It is intentionally detailed so the team can directly convert it into PowerPoint/Canva slides while keeping the story consistent with the implemented system and validated benchmarks.

---

# SLIDE 1 — TITLE / PROBLEM STATEMENT

## AI-Powered Cyber Threat Intelligence

### Problem Statement — HNX26PSI03

**Challenge**

Modern organizations generate massive volumes of heterogeneous security telemetry. Individual events such as unusual logins, sensitive-file access, USB activity or abnormal network connections are often ambiguous.

The real challenge is:

> **How can we reconstruct a complete multi-stage cyber attack from fragmented security evidence while suppressing benign activity, identity collisions, missing telemetry, decoys and time drift?**

### Our Solution

**An evidence-first Cyber Threat Intelligence engine that converts heterogeneous security logs into validated attack campaigns.**

### Core principle

~~~text
Anomaly ≠ Incident

Evidence
   ↓
Correlation
   ↓
Reconstruction
   ↓
Validated Incident
~~~

### What we deliver

- Multi-source security-log ingestion
- Canonical event normalization
- Entity-aware correlation
- Behavioral anomaly signals
- Temporal attack reconstruction
- Evidence coverage analysis
- Campaign hypotheses for incomplete evidence
- Deterministic incident validation
- MITRE ATT&CK enrichment
- Grounded AI investigation
- Explainable response recommendations

### Team Pitch

> **We do not alert because one event looks suspicious. We validate an attack only when independent evidence forms a coherent, entity-consistent and temporally valid chain.**

---

# SLIDE 2 — WHY EXISTING APPROACHES FAIL

## The Real Problem Is Correlation, Not Detection

### Traditional approach

~~~text
Single anomaly
     ↓
Threshold
     ↓
Alert
~~~

This creates alert fatigue because legitimate activity can also look anomalous.

### Failure modes we explicitly address

| Challenge | Why naive systems fail | Our response |
|---|---|---|
| Huge clean logs | Look-elsewhere false positives | Evidence-gated reconstruction |
| AND-gating | Recall collapses when one stage is missing | Campaign hypotheses |
| Benign lookalikes | Legitimate backup/admin actions resemble attacks | Authorization + entity + evidence checks |
| IP ambiguity | DHCP/NAT/shared IPs cause wrong attribution | Multi-entity resolution |
| Clock drift | Fixed windows miss slow attacks | Bounded adaptive temporal reasoning |
| Decoys | Earliest matching event may be unrelated | Ordered stage-path reconstruction |
| Missing telemetry | Binary detector incorrectly says benign | Explicit missing-stage hypothesis |
| Cross-user activity | Events from two users get stitched | Cross-identity/device conflict checks |
| LLM hallucination | AI may invent unsupported conclusions | LLM only after deterministic validation |

### Key insight

> **A high anomaly score is not proof of an attack.**

The detector must establish:

~~~text
WHO + WHAT + WHEN + WHERE + WHY THESE EVENTS BELONG TOGETHER
~~~

---

# SLIDE 3 — PROPOSED SOLUTION

## Evidence-First Attack Reconstruction

### End-to-end architecture

~~~text
Security Logs
     │
     ├── Windows Security
     ├── Windows XML
     ├── Sysmon
     └── Zeek
     │
     ▼
Event Adapters
     │
     ▼
Canonical SecurityEvent
     │
     ▼
Entity Resolution
     │
     ▼
Behavior Signals
     │
     ▼
Temporal + Entity Correlation
     │
     ▼
Attack-Stage Reasoner
     │
     ▼
Evidence Coverage
     │
     ▼
Deterministic Reconstruction
     │
     ▼
Campaign Confidence
     │
     ├───────────────┐
     ▼               ▼
Validated       Incomplete
Incident        Campaign
     │           Hypothesis
     ▼
ATT&CK + Response
     │
     ▼
Grounded LLM Investigator
~~~

### Demonstrated attack chain

~~~text
Suspicious Login
      ↓
New / Relevant Device Context
      ↓
Sensitive File Access
      ↓
Removable Media
      ↓
Large File Copy / Exfiltration
      ↓
Validated Campaign
~~~

### Critical separation

**Detection engine = deterministic security decision**

**LLM = optional investigator/explainer**

The LLM cannot create an incident or invent evidence.

---

# SLIDE 4 — TECHNICAL ARCHITECTURE & TECHNOLOGIES

## Technology Stack

### Backend

- **Python 3.11**
- FastAPI / Python service layer
- Pydantic-style structured models
- Deterministic correlation and reconstruction engine
- Pytest-based validation

### Security telemetry

- Windows Security Event Logs
- Windows XML Event Logs
- Sysmon
- Zeek conn / HTTP / DNS
- Public security datasets
- CERT Insider Threat Test Dataset r4.2

### Intelligence

- MITRE ATT&CK Enterprise
- Pinned ATT&CK knowledge base
- Demonstrated mappings:
  - T1078 — Valid Accounts
  - T1005 — Data from Local System
  - T1052.001 — Exfiltration over USB

### AI / LLM

- OpenAI-compatible LLM investigator
- Temperature 0
- Structured output
- Evidence-ID citations
- Deterministic grounding validation
- No synthetic fallback

### Frontend

- Web dashboard
- Attack timeline
- Entity graph
- Stage evidence
- Reconstruction details
- ATT&CK intelligence
- Response actions
- Validation / suppression status

### Core design decision

> **No black-box ML model is required for the security-critical incident gate.**

ML/LLM capabilities can provide bounded signals or explanations, while deterministic evidence requirements remain authoritative.

---

# SLIDE 5 — DATA SOURCES & DATA PIPELINE

## Where Our Data Comes From

We deliberately use different datasets for different validation purposes.

### 1. Versioned project scenarios

Repository-controlled deterministic scenarios provide:

- Full attack
- Clean control
- Partial attack
- Reversed order
- Slow attack
- Mismatched entities
- Authorized transfer
- Benign backup
- Decoys
- Cross-user scenarios
- Simultaneous campaigns

**Purpose:** reproducible demo + regression testing.

### 2. Public security telemetry

Phase 8 public validation used Splunk Attack Data-derived telemetry.

Result:

- **6,208 records**
- **0 parse errors**
- **0 normalization errors**

**Purpose:** validate heterogeneous ingestion and normalization.

### 3. CERT Insider Threat Test Dataset r4.2

Raw benchmark sources:

~~~text
logon.csv
device.csv
file.csv
insiders.csv
~~~

Rows evaluated:

| File | Rows |
|---|---:|
| logon.csv | 854,859 |
| device.csv | 405,380 |
| file.csv | 445,581 |
| insiders.csv | 191 |

Official answer-key evaluation contained **70 malicious scenarios**.

### CERT interpretation

Only **3 / 70** scenarios matched our current removable-media evidence contract.

~~~text
3 / 70 = 4.29%
~~~

This is **compatibility coverage, NOT detector recall**.

All 3 compatible cases completed the required ordered chain.

### Why this matters

We refuse to report a misleading recall number when the dataset contains attack types outside our current evidence contract.

---

# SLIDE 6 — CORE ALGORITHM / HOW IT WORKS

## From Raw Logs to a Proven Incident

### Step 1 — Normalize

Different log formats become:

~~~text
SecurityEvent
├── timestamp
├── user
├── device
├── src_ip
├── dst_ip
├── event_type
├── action
├── resource
├── session
└── metadata
~~~

### Step 2 — Resolve entities

The system correlates:

- User
- Device
- IP
- Session
- Resource
- Process

**IP alone is never treated as identity.**

### Step 3 — Generate behavior signals

Examples:

- unusual login time
- unknown device
- unusual source
- abnormal event frequency
- unusual application

Behavior contributes evidence but cannot bypass the incident gate.

### Step 4 — Identify attack stages

Mandatory stages:

~~~text
Identity / Initial Access
        ↓
Sensitive Data Access
        ↓
Collection / Exfiltration
~~~

### Step 5 — Validate temporal order

A valid chain requires:

~~~text
Identity timestamp
≤
Sensitive-data timestamp
≤
Exfiltration timestamp
~~~

Input order is not trusted.

### Step 6 — Validate entity consistency

Mandatory evidence must belong to a coherent user/device context.

Cross-user contamination causes the system to fail closed.

### Step 7 — Reconstruct

The reconstructor stores:

- selected evidence IDs
- rejected decoys
- stage relationships
- temporal validity
- entity consistency
- reconstruction score
- edge reasons

### Step 8 — Decide

~~~text
Complete + valid evidence
        ↓
VALIDATED INCIDENT

Incomplete but coherent
        ↓
CAMPAIGN HYPOTHESIS

Contradictory / unsupported
        ↓
SUPPRESSED
~~~

---

# SLIDE 7 — AI, ATT&CK & EXPLAINABILITY

## AI Works on Top of Evidence

### Deterministic security gate

The detector decides whether an incident exists using:

- required stages
- exact event evidence
- temporal validity
- entity consistency
- authorization checks
- reconstruction validity
- contradiction checks

### MITRE ATT&CK

ATT&CK is used for **enrichment**, not incident creation.

~~~text
Evidence
   ↓
Validated behavior
   ↓
ATT&CK mapping
   ↓
Threat context
~~~

### Grounded LLM Investigator

Only after deterministic validation:

~~~text
Validated Incident
      ↓
Sealed Evidence Packet
      ↓
LLM Investigator
      ↓
Explanation
      ↓
Event-ID Grounding Check
~~~

### Security boundaries

The LLM:

- cannot create incidents
- cannot create evidence
- cannot override deterministic validation
- cannot treat log text as instructions
- must cite exact evidence IDs
- fails closed when grounding fails

### Explainability output

Every validated campaign can show:

**What?** — attack stage

**When?** — timestamped evidence

**Who?** — user/entity

**Where?** — device/network context

**Why connected?** — causal relationship

**Why not benign?** — contradiction/authorization checks

**What next?** — response recommendation

---

# SLIDE 8 — VALIDATION, RESULTS & NOVELTY

## We Attacked Our Own Detector

### Phase 11 — Adversarial benchmark

**26 cases**

Included:

- baseline attacks
- noisy attacks
- slow attacks
- clock drift
- duplicate events
- decoys
- missing telemetry
- partial evidence
- shared-IP collisions
- cross-entity contamination
- simultaneous campaigns
- two users sharing one device
- identity-stage swaps
- 5,000-event benign haystacks

Results:

| Metric | Result |
|---|---:|
| Validated-incident precision | **100%** |
| Benign validated FPR | **0%** |
| Campaign coverage recall | **100%** |
| Campaign coverage FPR | **0%** |

### Phase 12 — Confidence & drift

Validated:

- slow/long-spacing attack handling
- benign false-positive protection
- confidence separation for incomplete evidence

A naive global 90-minute window caused false positives and was rejected.

### Phase 13 — Generalization

Unseen/transformed cases included:

- rotated structure
- interleaved benign activity
- decoy-heavy attack
- missing device telemetry
- simultaneous campaigns
- benign lookalikes
- large haystacks

Gate:

- malicious validated recall: **100%**
- benign validated FPR: **0%**

### Phase 14 — Robustness

Stress included:

- **20,000 benign events + attack**
- **20,000 benign events only**
- duplicate attack events
- reversed input order

Final robustness gate passed.

### Novelty

1. Evidence-first incident gating
2. Explicit incomplete-campaign hypotheses
3. Deterministic causal reconstruction
4. Cross-identity protection
5. Bounded adaptive temporal reasoning
6. LLM as investigator, not judge
7. Adversarial self-validation

---

# SLIDE 9 — BUSINESS MODEL CANVAS

## Business Model Canvas — AI Cyber Threat Intelligence Platform

**Business model positioning:**

> **A B2B cybersecurity intelligence and incident-reconstruction platform for organizations that need high-confidence, explainable threat detection without overwhelming SOC analysts with false alerts.**

---

## 1 — CUSTOMER SEGMENTS

### Primary

- Enterprise SOC teams
- Security Operations Centers
- Financial institutions
- Healthcare organizations
- Government / public-sector organizations
- Critical infrastructure operators
- Large technology companies

### Secondary

- MSSPs / MDR providers
- Managed security teams
- Security consultants
- Universities and research institutions
- Mid-sized organizations without mature SOC infrastructure

### Buyer personas

- CISO
- SOC Manager
- Security Engineer
- Threat Hunter
- Incident Responder
- Security Operations Analyst

---

## 2 — VALUE PROPOSITION

### Primary value

**Reduce false-positive alert fatigue while preserving high-confidence attack detection.**

### What we provide

- Evidence-backed incidents
- Multi-stage attack reconstruction
- Exact evidence IDs
- Explainable timelines
- Entity-aware correlation
- Missing-evidence hypotheses
- Benign suppression
- MITRE ATT&CK context
- Grounded AI investigation
- Faster analyst triage

### Business outcome

~~~text
Millions of events
       ↓
Fewer high-confidence investigations
       ↓
Less analyst time wasted
       ↓
Faster incident response
       ↓
Lower security-operation cost
~~~

---

## 3 — CHANNELS

### Direct

- Enterprise sales
- Security-team pilots
- Proof-of-concept deployments
- SIH / hackathon demonstration
- Cybersecurity conferences

### Technical

- GitHub
- Developer documentation
- API integrations
- SIEM integrations
- EDR integrations

### Partner

- MSSPs
- MDR providers
- Cloud/security consultants
- Enterprise IT vendors

---

## 4 — CUSTOMER RELATIONSHIPS

### Enterprise

- Dedicated onboarding
- Security architecture consultation
- Integration support
- SLA-backed support
- Continuous threat-rule updates

### Product

- Self-service dashboard
- Documentation
- API
- Automated reports
- Incident investigation workspace

### Long-term

- Threat-model customization
- Organization-specific baselines
- Custom evidence contracts
- Analyst feedback loops

---

## 5 — REVENUE STREAMS

### SaaS subscription

Tiered pricing based on:

- event volume
- endpoints
- analysts
- retention
- integrations

### Enterprise licensing

For large organizations requiring:

- private deployment
- dedicated infrastructure
- custom integrations
- advanced support

### MSSP / MDR licensing

Multi-tenant pricing for managed security providers.

### Professional services

- deployment
- SIEM integration
- detection engineering
- threat-model customization
- SOC workflow integration

---

## 6 — KEY RESOURCES

### Technology

- Correlation engine
- Evidence graph/reconstruction engine
- Detection rules
- Entity-resolution logic
- ATT&CK knowledge base
- Grounded AI investigator

### Data

- Security telemetry
- Public validation datasets
- Threat intelligence
- Organization-specific baselines

### Human resources

- Security researchers
- Detection engineers
- ML/AI engineers
- Backend engineers
- SOC analysts

### Infrastructure

- Event processing
- Storage
- Search/indexing
- Model/LLM infrastructure
- Monitoring

---

## 7 — KEY ACTIVITIES

- Security-log ingestion
- Event normalization
- Detection engineering
- Attack reconstruction
- Threat-intelligence enrichment
- Entity resolution
- False-positive reduction
- Benchmarking
- Threat hunting
- Model/LLM grounding
- Continuous regression testing
- SOC workflow integration

### Core operational loop

~~~text
BUILD
 ↓
TEST
 ↓
BREAK
 ↓
FIX
 ↓
REGRESSION
 ↓
GATE
~~~

---

## 8 — KEY PARTNERS

### Security ecosystem

- SIEM providers
- EDR/XDR providers
- Cloud-security platforms
- Threat-intelligence providers
- Identity/security vendors

### Data / research

- CERT / SEI-style research datasets
- MITRE ATT&CK ecosystem
- Security research communities
- Universities

### Commercial

- MSSPs
- MDR providers
- Cybersecurity consultants
- Enterprise technology integrators

---

## 9 — COST STRUCTURE

### Technology costs

- Cloud compute
- Event storage
- Log indexing
- Database infrastructure
- LLM/API usage
- Monitoring

### Engineering costs

- Detection engineering
- Backend/frontend development
- Security research
- QA and adversarial testing

### Operational costs

- Customer support
- Security operations
- Compliance
- Data acquisition
- Infrastructure maintenance

### Cost optimization strategy

Deterministic correlation handles the security-critical path first.

LLM usage is only applied where it adds analyst value.

~~~text
All logs → deterministic processing
                  ↓
         High-value incidents
                  ↓
            LLM investigation
~~~

This reduces unnecessary model cost and limits AI attack surface.

---

# BUSINESS MODEL SUMMARY

| Canvas Block | Our Answer |
|---|---|
| Customer Segments | Enterprises, SOCs, BFSI, healthcare, government, critical infrastructure, MSSPs |
| Value Proposition | High-confidence, explainable multi-stage attack reconstruction with fewer false positives |
| Channels | Enterprise sales, pilots, SIH/demo, GitHub, integrations, MSSP partners |
| Customer Relationships | Self-service + enterprise onboarding + continuous security support |
| Revenue Streams | SaaS, enterprise licensing, MSSP licensing, professional services |
| Key Resources | Detection engine, evidence graph, telemetry, ATT&CK, AI investigator, security team |
| Key Activities | Detection, correlation, reconstruction, threat intelligence, testing, SOC integration |
| Key Partners | SIEM/EDR/cloud vendors, MSSPs, research ecosystem, security integrators |
| Cost Structure | Cloud, storage, engineering, LLM usage, support, security/compliance |

---

# FINAL PRESENTATION CLOSING

## The Problem

Security teams have too much telemetry and too many ambiguous alerts.

## Our Answer

We reconstruct attacks from evidence instead of treating anomalies as incidents.

## Our Differentiator

~~~text
Anomaly
   ↓
Evidence
   ↓
Entity + Time
   ↓
Causal Reconstruction
   ↓
Validated Campaign
   ↓
Grounded AI Explanation
~~~

## Final Pitch

> **“We don't alert because one event looks suspicious. We prove an incident by reconstructing an evidence-backed, entity-consistent and temporally valid attack chain — and we show the exact evidence that proves it.”**

---

# SLIDE DESIGN GUIDANCE

For the final PowerPoint/Canva deck, keep the visual structure close to the SIH style:

### Slide 1
Problem + project identity + one-line solution.

### Slide 2
Problem weaknesses / why current approaches fail.

### Slide 3
Proposed architecture.

### Slide 4
Technical stack and components.

### Slide 5
Datasets and data pipeline.

### Slide 6
Core algorithm / evidence reconstruction.

### Slide 7
AI + ATT&CK + explainability.

### Slide 8
Results + novelty.

### Slide 9
**Business Model Canvas** using the provided 9-block layout.

For the Business Model slide, use the supplied orange/black canvas structure and place the nine numbered sections exactly as:

~~~text
             TOP
8 Key Partners | 7 Key Activities | 2 Value Proposition | 4 Customer Relationship | 1 Customer Segments

             MIDDLE
                 6 Key Resources                    | 3 Channels

             BOTTOM
9 Cost Structure                                    | 5 Revenue Streams
~~~

This preserves the numbering shown in the supplied reference image while adapting every block to the cyber-threat-intelligence product.

---

# FINAL MESSAGE TO JUDGES

> **Evidence first. Explanation second.**
>
> Our system is not another anomaly detector that turns every unusual event into an alert. It is an evidence-first cyber threat intelligence engine that reconstructs multi-stage campaigns, explicitly represents uncertainty, rejects identity and temporal contradictions, suppresses benign lookalikes, and uses AI only where it can remain grounded in validated evidence.
