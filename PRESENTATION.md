# SIH 2026 PRESENTATION
## HNX26PSI03 — AI-Powered Cyber Threat Intelligence

> **Presentation master document — 8 core SIH slides + 1 Business Model Canvas slide**
>
> **Core principle: Evidence first, explanation second.**

---

# SLIDE 1 — TITLE + PROBLEM STATEMENT

## AI-Powered Cyber Threat Intelligence

### HNX26PSI03

### The Problem

Modern organizations generate huge volumes of heterogeneous security telemetry:

- Windows authentication and security logs
- Sysmon process, file and network events
- Endpoint/device activity
- DNS / HTTP / network telemetry
- File access and data movement
- USB / removable-media activity

The challenge is **not simply finding an unusual event**.

The real problem is:

> **How do we determine whether fragmented, individually weak events form one coherent multi-stage cyber attack while avoiding false incidents caused by benign activity, missing telemetry, identity ambiguity, time drift and decoys?**

### Our answer

**An evidence-first Cyber Threat Intelligence engine that reconstructs attack campaigns from heterogeneous security logs and validates an incident only when the required evidence forms a coherent chain.**

### Core message

```
Anomaly ≠ Incident

Events
  ↓
Evidence
  ↓
Correlation
  ↓
Reconstruction
  ↓
Validated Incident
```

### Demonstrated attack

```
Suspicious Login
      ↓
Sensitive File Access
      ↓
Removable Media
      ↓
Large Data Copy
      ↓
Validated Campaign
```

---

# SLIDE 2 — EXISTING GAP / WHY CURRENT APPROACHES FAIL

## Why Anomaly Detection Alone Is Not Enough

A traditional security pipeline often behaves like:

```
Suspicious event
      ↓
Threshold
      ↓
Alert
```

This creates false positives because legitimate activity can also be unusual.

### The six major gaps we target

| Existing weakness | Failure | Our approach |
|---|---|---|
| Look-elsewhere problem | Huge clean logs produce accidental chains | Evidence-gated reconstruction |
| AND-gating | Missing one stage collapses detection | Explicit Campaign Hypothesis |
| Benign lookalikes | Admin/backup activity resembles attacks | Authorization + entity + evidence checks |
| Identity stitching | IP/device sharing combines unrelated users | Multi-entity consistency + fail-closed rules |
| Fixed time windows | Slow attacks are missed | Bounded adaptive temporal reasoning |
| Decoys/noise | First matching event may be unrelated | Ordered causal stage-path reconstruction |

### Critical distinction

**Anomaly score answers:**

> “Is this event unusual?”

**Campaign confidence answers:**

> “Do these exact events form one coherent attack?”

**Validated incident answers:**

> “Do we have enough evidence to call this an attack?”

### Design philosophy

> **We optimize for defensible incidents, not maximum alert volume.**

---

# SLIDE 3 — PROPOSED SOLUTION

## Evidence-First Attack Reconstruction

### End-to-end concept

```
Heterogeneous Security Logs
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
Deterministic Reconstruction
          ↓
Campaign Confidence
          ↓
┌─────────────────────────────┐
│ Complete coherent evidence? │
└─────────────────────────────┘
       ↓ YES             ↓ NO
Validated Incident   Hypothesis / Silent
       ↓
Timeline + Evidence
+ ATT&CK + Response
       ↓
Optional Grounded LLM
Investigation
```

### Attack contract

For the demonstrated removable-media campaign:

```
Identity / Initial Access
          ↓
Sensitive Data Access
          ↓
Collection / Exfiltration
```

A validated incident requires:

- mandatory stages
- exact event evidence
- valid temporal ordering
- coherent entity context
- sufficient reconstruction confidence
- no blocking authorization/contradiction

### Missing evidence

```
Complete chain → VALIDATED INCIDENT

2 compatible stages → CAMPAIGN HYPOTHESIS

Contradictory / unsupported → SILENT
```

This prevents the system from turning uncertainty into false certainty.

---

# SLIDE 4 — ARCHITECTURE + TECHNOLOGY STACK

## Technical Architecture

```
Windows Security ─┐
Windows XML ──────┤
Sysmon ───────────┤
Zeek ─────────────┘
        ↓
    ADAPTERS
        ↓
Canonical SecurityEvent
        ↓
Entity Resolution
        ↓
Behavior Engine
        ↓
Temporal / Entity Correlation
        ↓
Stage Reasoner
        ↓
Evidence Graph / Reconstruction
        ↓
Incident Gate
        ↓
Dashboard + ATT&CK + Response
        ↓
Optional Grounded LLM
```

### Core technologies

**Backend**
- Python 3.11
- FastAPI/service layer
- Structured security-event models
- Deterministic correlation engine
- Pytest regression framework

**Security telemetry**
- Windows Security 4624 / 4663
- Windows XML
- Sysmon 1 / 3 / 11 / 22
- Zeek conn / HTTP / DNS

**Threat intelligence**
- MITRE ATT&CK Enterprise
- Pinned ATT&CK knowledge base

**AI**
- Optional OpenAI-compatible LLM
- Temperature 0
- Structured output
- Evidence-ID grounding validation

**Frontend**
- Interactive detection dashboard
- Attack timeline
- Entity graph
- Evidence inspection
- ATT&CK and response views

### Important engineering decision

> **The security-critical incident gate is deterministic. AI assists investigation; it does not decide whether an incident exists.**

---

# SLIDE 5 — DATA SOURCES + MODELS

## Where Our Data Comes From

We use different data sources for different validation purposes.

### 1. Versioned project scenarios

Repository-controlled scenarios provide reproducible:

- full attacks
- clean controls
- partial evidence
- reversed order
- slow attacks
- mismatched entities
- authorized transfers
- benign backups
- decoys
- cross-user cases
- simultaneous campaigns

**Purpose:** demo + regression + judge reproducibility.

### 2. Public security telemetry

Phase 8 heterogeneous-ingestion validation:

- **6,208 records**
- **0 parse errors**
- **0 normalization errors**

**Purpose:** validate adapters and canonical normalization.

### 3. CERT Insider Threat Test Dataset r4.2

Raw benchmark inputs:

| File | Rows |
|---|---:|
| logon.csv | 854,859 |
| device.csv | 405,380 |
| file.csv | 445,581 |
| insiders.csv | 191 |

Evaluated answer-key set:

- **70 malicious scenarios**

Only **3/70** matched the project's current removable-media evidence contract.

```
3 / 70 = 4.29%
```

**This is compatibility/coverage, NOT detector recall.**

All 3 compatible cases completed the required ordered evidence chain.

### What models are used?

**Core detector:** deterministic evidence reasoning — no black-box ML required.

**Behavior layer:** deterministic baselines and bounded scoring.

**Threat intelligence:** MITRE ATT&CK.

**AI layer:** optional grounded LLM investigator after deterministic validation.

### Why this model strategy?

Security decisions need:

- reproducibility
- exact evidence attribution
- auditability
- predictable failure modes
- protection against hallucinated evidence

---

# SLIDE 6 — HOW THE SYSTEM WORKS

## From Raw Logs to a Proven Campaign

### Step 1 — Normalize

All adapters produce a common `SecurityEvent`:

```
event_id
timestamp
user
device
src_ip / dst_ip
event_type
action
resource
session
metadata
```

### Step 2 — Resolve entities

We correlate:

- user
- device
- IP
- session
- resource
- process/application

**IP address alone is never treated as identity.**

### Step 3 — Generate behavior signals

Examples:

- unknown source
- unknown device
- unusual hour
- unusual application
- abnormal event frequency

These are supporting signals, not incident proof.

### Step 4 — Identify stages

```
Identity / Initial Access
          ↓
Sensitive Data Access
          ↓
Collection / Exfiltration
```

### Step 5 — Validate time

A valid causal path must satisfy:

```
Identity time
    ≤
Sensitive-data time
    ≤
Exfiltration time
```

Input order is not trusted.

### Step 6 — Validate entities

Events must belong to a coherent user/device/session context.

Cross-user contamination can force a **fail-closed** decision.

### Step 7 — Reconstruct the campaign

The system records:

- selected event IDs
- rejected/decoy event IDs
- stage relationships
- temporal validity
- entity consistency
- reconstruction score
- edge reasons
- conflicts

### Step 8 — Decide

```
Complete + coherent
        ↓
VALIDATED INCIDENT

Incomplete but coherent
        ↓
CAMPAIGN HYPOTHESIS

Unsupported / contradictory
        ↓
SILENT
```

---

# SLIDE 7 — OUR NOVELTY

## What Is Actually Novel About Our Approach?

> **Our novelty is not “we use AI.” Our novelty is how evidence, uncertainty, identity, time and AI are controlled together.**

### 01 — Evidence-First Incident Gating

An anomaly never directly becomes an incident.

A validated incident requires independent evidence across mandatory attack stages.

### 02 — Explicit Incomplete-Campaign Hypotheses

When telemetry is missing, the system does not force a binary attack/benign decision.

It produces:

```
Observed stages
+ Missing stage
+ Evidence IDs
+ Confidence
+ Reason
```

**Hypothesis ≠ Incident.**

### 03 — Deterministic Causal Reconstruction

We do not merely find matching events.

We reconstruct:

- which events were selected
- which were rejected as decoys
- why stages are connected
- temporal relationships
- entity relationships

### 04 — Cross-Identity Protection

The system explicitly protects against:

- shared IPs
- shared devices
- multiple users
- identity-stage swaps
- cross-campaign contamination

When attribution becomes unsafe, we **fail closed**.

### 05 — Bounded Adaptive Temporal Reasoning

We rejected the naive solution of simply making the global time window huge.

Instead:

```
Normal window
     +
stronger identity/session continuity
     +
ordered-stage validation
     ↓
bounded drift tolerance
```

This supports slow attacks without opening the detector to look-elsewhere false positives.

### 06 — LLM as Investigator, Not Judge

The LLM cannot:

- create an incident
- invent evidence
- override deterministic validation
- treat logs as instructions

It receives a sealed evidence packet and explains validated evidence.

### 07 — Adversarial Self-Validation

We deliberately attack our own detector using:

- decoys
- missing telemetry
- clock drift
- slow attacks
- shared identities
- simultaneous campaigns
- benign lookalikes
- large benign haystacks
- reversed input order

> **The detector must survive attacks from the attacker and from our own test suite.**

### One-line novelty

> **“We do not treat anomalies as incidents; we prove incidents by reconstructing an evidence-backed, entity-consistent and temporally valid attack chain.”**

---

# SLIDE 8 — VALIDATION + AI/ATT&CK + IMPACT

## We Did Not Stop at a Demo — We Attacked the Detector

### Phase 11 — Adversarial benchmark

**26 cases**

Included:

- baseline / noisy / slow attacks
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

### Results

| Gate | Result |
|---|---:|
| Validated-incident precision | **100%** |
| Benign validated FPR | **0%** |
| Campaign coverage recall | **100%** |
| Campaign coverage FPR | **0%** |

### Phase 13 — Generalization

Unseen/transformed attacks included:

- rotated attack structure
- interleaved benign activity
- decoy-heavy attacks
- missing device telemetry
- different entity combinations
- simultaneous campaigns
- benign lookalikes
- large haystacks

**Malicious validated recall: 100%**

**Benign validated FPR: 0%**

### Phase 14 — Robustness

Stress tested with:

- **20,000 benign events + real attack**
- **20,000 benign events only**
- duplicate attack events
- reversed input order

Final robustness gate passed.

### ATT&CK enrichment

Demonstrated mappings:

- **T1078 — Valid Accounts**
- **T1005 — Data from Local System**
- **T1052.001 — Exfiltration over USB**

ATT&CK explains validated behavior; it does not create incidents.

### AI boundary

```
Deterministic Evidence
        ↓
Validated Incident
        ↓
Sealed Evidence Packet
        ↓
Grounded LLM
        ↓
Human-readable Investigation
```

### Expected operational impact

```
Massive telemetry
      ↓
Fewer unsupported alerts
      ↓
Evidence-backed incidents
      ↓
Faster analyst triage
      ↓
Better explainability
```

---

# SLIDE 9 — BUSINESS MODEL CANVAS

## AI Cyber Threat Intelligence Platform

**Positioning:** B2B cybersecurity intelligence and incident-reconstruction platform for organizations that need high-confidence, explainable threat detection without overwhelming SOC analysts.

### 1 — CUSTOMER SEGMENTS

- Enterprise SOC teams
- BFSI / financial institutions
- Healthcare
- Government
- Critical infrastructure
- Technology companies
- MSSPs / MDR providers
- Security consulting teams

**Buyers:** CISO, SOC Manager, Threat Hunter, Incident Responder, Security Engineer.

### 2 — VALUE PROPOSITION

- High-confidence multi-stage attack reconstruction
- Fewer false-positive investigations
- Exact evidence-backed incidents
- Explainable timelines
- Entity-aware correlation
- Missing-evidence hypotheses
- MITRE ATT&CK context
- Grounded AI investigation
- Faster analyst triage

### 3 — CHANNELS

- Enterprise sales
- Security-team pilots
- Proof-of-concept deployments
- SIH / cybersecurity demonstrations
- GitHub / developer community
- SIEM / EDR integrations
- MSSP partnerships

### 4 — CUSTOMER RELATIONSHIP

- Self-service dashboard
- API + documentation
- Enterprise onboarding
- Integration support
- SLA-backed support
- Custom threat-model configuration
- Continuous security updates

### 5 — REVENUE STREAMS

- SaaS subscription
- Event-volume / endpoint-based pricing
- Enterprise licensing
- Private deployment
- MSSP / MDR multi-tenant licensing
- Professional integration services

### 6 — KEY RESOURCES

- Detection/correlation engine
- Evidence reconstruction engine
- Security telemetry
- Threat intelligence
- ATT&CK knowledge base
- Grounded AI investigator
- Security engineering team
- Cloud/event-processing infrastructure

### 7 — KEY ACTIVITIES

- Log ingestion
- Normalization
- Detection engineering
- Entity resolution
- Attack reconstruction
- Threat-intelligence enrichment
- Threat hunting
- Adversarial testing
- SOC integration
- Continuous regression

### 8 — KEY PARTNERS

- SIEM providers
- EDR/XDR providers
- Cloud-security platforms
- Threat-intelligence providers
- MSSPs / MDR providers
- Security consultants
- Universities / research ecosystem
- Enterprise technology integrators

### 9 — COST STRUCTURE

- Cloud compute
- Event storage and indexing
- Database infrastructure
- LLM/API usage
- Engineering
- Security research
- QA / adversarial testing
- Customer support
- Compliance and infrastructure maintenance

### Business-model logic

```
Security telemetry
      ↓
Evidence reconstruction
      ↓
High-confidence incidents
      ↓
Lower analyst investigation cost
      ↓
Enterprise value
      ↓
SaaS / Enterprise / MSSP revenue
```

### Cost-control advantage

The expensive generative layer is **not** applied to every raw event.

```
All telemetry
     ↓
Deterministic processing
     ↓
High-value validated evidence
     ↓
LLM investigation only where useful
```

This reduces AI cost and reduces the LLM attack surface.

---

# PRESENTATION CLOSING — USE AFTER SLIDE 9

## The Problem

Security teams have too much telemetry and too many ambiguous alerts.

## Our Solution

We reconstruct attacks from evidence instead of treating anomalies as incidents.

## Our Strongest Differentiator

```
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
```

## Final 15-Second Pitch

> **“We don't alert because one event looks suspicious. We prove an incident by reconstructing an evidence-backed, entity-consistent and temporally valid attack chain. If evidence is missing, we show the uncertainty instead of inventing certainty.”**

---

# SIH PRESENTATION DESIGN ORDER

| Slide | Purpose |
|---|---|
| 1 | Problem + solution identity |
| 2 | Existing gap / why current approaches fail |
| 3 | Proposed solution |
| 4 | Architecture + technology stack |
| 5 | Data sources + models |
| 6 | How the algorithm works |
| 7 | **NOVELTY — dedicated judge-facing slide** |
| 8 | Validation + AI/ATT&CK + impact |
| 9 | **Business Model Canvas** |

### Important

The supplied Business Model Canvas reference image should be used for Slide 9 with the exact numbered block mapping:

```
8 Key Partners | 7 Key Activities | 2 Value Proposition | 4 Customer Relationship | 1 Customer Segments
6 Key Resources | 3 Channels
9 Cost Structure | 5 Revenue Streams
```

The content above is written specifically for those nine blocks.

---

# FINAL JUDGE MESSAGE

> **Evidence first. Explanation second.**
>
> We built an evidence-first cyber threat intelligence engine that reconstructs multi-stage attacks from heterogeneous security telemetry, explicitly represents incomplete evidence, protects against identity and temporal stitching errors, suppresses benign lookalikes, and uses AI only on validated evidence.
>
> **We are not building another alert generator. We are building a system that can explain why an incident is actually proven.**
