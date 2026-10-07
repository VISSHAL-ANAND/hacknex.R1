# SOLUTION — HNX26PSI03
## AI-Powered Cyber Threat Intelligence

> **Evidence first, explanation second.**

This document is the complete technical solution note for **HNX26PSI03 — AI-Powered Cyber Threat Intelligence**. It explains the problem, our approach, data sources, models, architecture, evidence correlation, AI/LLM role, evaluation, limitations, production path, novelty and likely judge questions.

---

# 1. Problem We Are Solving

Modern security environments generate enormous volumes of heterogeneous telemetry: Windows authentication logs, Windows security events, Sysmon process/file/network events, endpoint/device events, DNS/HTTP/network telemetry, file access and data movement events, removable-media activity and threat-intelligence context.

The difficult problem is not simply detecting an unusual event.

> **How do we determine whether many individually weak or ambiguous events are actually parts of one coherent multi-stage attack, while avoiding false incidents caused by benign activity, missing telemetry, identity ambiguity, time drift, noise and unrelated events?**

Our solution reconstructs attacks from evidence rather than declaring incidents from isolated anomalies.

---

# 2. Our Core Answer

~~~text
Heterogeneous Security Logs
        ↓
Normalization
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
Complete coherent chain?
        ↓ YES                 ↓ NO
Validated Incident       Hypothesis / Silent
        ↓
Timeline + Evidence + ATT&CK + Response
        ↓
Optional Grounded LLM Investigation
~~~

The central rule is:

> **An anomaly is evidence. It is not an incident.**

---

# 3. What Our System Detects

The demonstrated attack contract is a multi-stage insider/endpoint data-theft pattern:

~~~text
1. Suspicious / unusual identity activity
                 ↓
2. Sensitive data access
                 ↓
3. Collection / exfiltration
                 ↓
4. Correlated attack campaign
~~~

For the removable-media path, the system looks for identity/login evidence, device context, sensitive file access, removable-media/USB activity, large file-copy activity, temporal continuity and entity continuity.

The final incident requires all mandatory stages to be supported by evidence.

---

# 4. Why We Do NOT Use "Anomaly = Attack"

A naive solution might do:

~~~text
anomaly score > threshold
        ↓
ALERT
~~~

This produces false positives.

For example:

~~~text
Admin logs in unusually late
        ↓
Admin accesses sensitive backup
        ↓
Admin copies backup to USB
~~~

This can look exactly like an attack at the individual-event level while being legitimate.

Therefore our system separates:

1. **Signal** — something unusual happened.
2. **Evidence** — multiple events support a possible attack stage.
3. **Campaign hypothesis** — compatible stages exist but evidence is incomplete.
4. **Validated incident** — all mandatory stages form one temporally valid and entity-consistent chain.

Only Level 4 becomes a validated incident.

---

# 5. Complete System Architecture

## Ingestion

Supported telemetry includes:

- Windows Security 4624 — logon
- Windows Security 4663 — object/file access
- Windows Event Log XML
- Sysmon 1 / 3 / 11 / 22
- Zeek conn / HTTP / DNS
- Canonical SecurityEvent records

All sources are converted into the internal SecurityEvent representation.

---

# 6. Event Normalization

Different log sources use different field names.

~~~text
Windows:
SubjectUserName
IpAddress
WorkstationName

Sysmon:
User
Image
SourceIp
DestinationIp

Zeek:
id.orig_h
id.resp_h
uid
query
~~~

Instead of writing the detector separately for every format, we normalize them into one schema:

~~~text
Raw Event
   ↓
Adapter
   ↓
SecurityEvent
   ├── event_id
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

This allows the correlation engine to operate independently of the original log format.

---

# 7. Entity Resolution

We maintain contextual identity fields:

- user
- device
- source IP
- destination IP
- session
- resource
- process/application

### Important design decision

**IP address is not treated as identity.**

Why?

- DHCP changes IP ownership
- NAT shares addresses
- proxies hide source identity
- multiple users can share infrastructure
- timestamps can drift

Therefore an IP match alone cannot stitch an attack.

Entity compatibility is calculated from multiple fields.

---

# 8. Behavior Signals

The behavior layer provides contextual evidence:

- known vs unknown source IP
- known vs unknown device
- unusual application
- unusual event type
- unusual activity hour
- abnormal event frequency

Behavior contributes to correlation confidence but does not independently create an incident.

~~~text
Behavior anomaly ≠ attack proof
~~~

---

# 9. Temporal Correlation

Attack stages must occur in a plausible sequence.

~~~text
09:12 Login
09:32 Sensitive file access
09:52 Large copy
~~~

is plausible.

~~~text
09:52 Large copy
09:32 Sensitive file access
09:12 Login
~~~

must not be accepted as a causal attack simply because the events exist.

## Temporal drift

A fixed narrow window can miss slow attacks.

A huge global window creates look-elsewhere false positives.

We therefore use bounded normal correlation, bounded drift tolerance, stronger identity/session continuity for extended gaps and ordered stage-path validation.

> **The time window can adapt only when the evidence relationship becomes stronger.**

---

# 10. Attack-Stage Reasoning

Mandatory stages are represented explicitly:

~~~text
Stage 1
Initial Access / Identity Anomaly
       ↓
Stage 2
Sensitive Data Access
       ↓
Stage 3
Collection / Exfiltration
~~~

Each stage contains actual event evidence.

A validated stage cannot exist without supporting event IDs.

---

# 11. Evidence-First Validation

Every incident must answer:

- What happened?
- When did it happen?
- Who was involved?
- Which device?
- Which exact logs prove it?
- Why are these events one campaign?
- Why is this not a benign lookalike?

The answers come from stage classification, timestamps, entity context, event IDs, temporal compatibility, entity compatibility and contradiction/authorization checks.

This makes the result explainable and auditable.

---

# 12. Causal Reconstruction

The reconstruction layer does not simply sort events.

It records:

- selected event IDs
- rejected/decoy event IDs
- stage relationships
- temporal validity
- entity compatibility
- reconstruction score
- edge reasons
- entity conflicts

Example:

~~~text
LOGIN-001
   │
   │ same user/device
   │
FILE-014
   │
   │ sensitive resource + ordered timing
   │
USB-009
   │
   │ removable destination + large copy
   │
COPY-017
~~~

The final result becomes an evidence graph rather than an unexplained alert.

---

# 13. Decoy Handling

Real environments contain unrelated events.

~~~text
Login
File Access
USB Mount
Benign Process
Sensitive File Access
Large Copy
~~~

The first USB event may be a decoy.

The detector therefore searches for a valid ordered stage path instead of assuming the earliest matching event is causal.

---

# 14. Cross-Identity Protection

One dangerous false-positive case is:

~~~text
Alice:
Login → Sensitive File

Bob:
USB → Large Copy
~~~

If they share a device/IP, a naive detector may stitch them together.

Our detector rejects cross-identity stage stitching.

When attribution is ambiguous, the system fails closed instead of inventing certainty.

---

# 15. Campaign Hypothesis

Missing telemetry should not necessarily mean "nothing happened."

~~~text
Login
  ↓
Sensitive File Access
  ↓
[USB evidence missing]
~~~

The system can produce a CampaignHypothesis containing:

- hypothesis ID
- confidence
- observed stages
- missing stages
- evidence event IDs
- temporal validity
- entity consistency
- explanation

But:

~~~text
Hypothesis ≠ Incident
~~~

---

# 16. Confidence Model

For incomplete campaign hypotheses we combine stage confidence, temporal validity and entity consistency with explicit caps.

Conceptually:

~~~text
Confidence =
    stage evidence
  + temporal validity
  + entity consistency
~~~

A high score cannot override:

- missing mandatory evidence
- entity contradiction
- impossible ordering
- authorization
- cross-user contamination

---

# 17. ATT&CK Intelligence

We use MITRE ATT&CK as contextual threat intelligence.

Current demonstrated mappings:

- **T1078 — Valid Accounts**
- **T1005 — Data from Local System**
- **T1052.001 — Exfiltration over USB**

The boundary is:

~~~text
ATT&CK mapping
      ↓
Enrichment
~~~

not:

~~~text
ATT&CK mapping
      ↓
Incident
~~~

The evidence comes from logs. ATT&CK explains the behavior.

---

# 18. Where AI / LLM Is Used

The deterministic engine is the security decision-maker.

The LLM is an optional investigator:

~~~text
Raw Logs
   ↓
Deterministic Detection
   ↓
Evidence Validation
   ↓
Validated Incident
   ↓
Sealed Evidence Packet
   ↓
LLM Investigator
   ↓
Human-readable Explanation
~~~

The investigator is constrained by:

- sealed evidence packet
- temperature 0
- structured output
- exact event-ID citations
- deterministic grounding validation
- no synthetic fallback
- fail-closed behavior

> **The LLM explains evidence. It does not manufacture evidence.**

---

# 19. What Models Are Actually Used?

## Core detection

There is **no black-box ML model required for the core detector**.

The security-critical decision engine is deterministic because evidence requirements must be auditable, reproducible and explainable.

## Behavioral model

Behavioral signals use deterministic baselines and bounded scoring.

## Threat intelligence

MITRE ATT&CK provides the threat-behavior knowledge base.

## Optional generative model

An OpenAI-compatible LLM is used only for grounded investigation/explanation.

The architecture intentionally avoids putting an LLM in the critical incident gate.

---

# 20. Where Our Data Comes From

We use multiple data categories for different purposes.

## 20.1 Reproducible project/demo data

The repository contains deterministic scenarios in:

~~~text
backend/data/scenarios.json
~~~

These are used for the full attack demonstration, clean control, adversarial cases, regression tests and judge demonstration.

Because they are versioned with the repository, anyone can reproduce the demonstrated behavior.

## 20.2 Public security telemetry

We validated heterogeneous log ingestion using public security datasets, including Splunk Attack Data.

Phase 8 public validation processed:

- **6,208 records**
- **0 parse errors**
- **0 normalization errors**

This validates ingestion/normalization. It is not presented as end-to-end detector recall.

## 20.3 CERT Insider Threat Test Dataset

We evaluated against the **CERT Insider Threat Test Dataset, release r4.2**.

Raw files:

~~~text
logon.csv
device.csv
file.csv
insiders.csv
~~~

Observed raw row counts:

| Dataset | Rows |
|---|---:|
| logon.csv | 854,859 |
| device.csv | 405,380 |
| file.csv | 445,581 |
| insiders.csv | 191 |

There were **70 malicious scenarios** in the evaluated answer-key set.

Only **3 / 70** malicious scenarios matched the project's current:

~~~text
identity
→ sensitive file activity
→ removable-media exfiltration
~~~

evidence contract.

Therefore **4.29% is a compatibility/coverage rate, not detector recall**.

All 3 compatible scenarios completed the project's ordered evidence chain.

---

# 21. Why CERT Cannot Directly Give Us Detector Recall

CERT is broader than our current removable-media evidence contract.

A malicious scenario may contain credential misuse, email exfiltration, web upload, unusual access, privilege abuse or other insider behavior without having the exact evidence required by our detector.

Counting those as detector false negatives would be scientifically incorrect.

Therefore we report:

1. dataset compatibility
2. stage-level proxy coverage
3. compatible ordered-chain coverage
4. benign proxy-chain rate

---

# 22. Raw CERT Results

| Metric | Result |
|---|---:|
| Malicious scenarios | 70 |
| Project-compatible scenarios | 3 |
| Compatibility rate | **4.29%** |
| Identity-stage proxy recall | **100%** |
| Sensitive-stage proxy recall | **5.71%** |
| Exfil-stage proxy recall | **4.29%** |
| Ordered-chain proxy recall | **4.29%** |
| Compatible ordered-chain recall | **100%** |
| Benign windows sampled | 300 |
| Benign proxy chains | 7 |
| Benign proxy-chain rate | **2.33%** |

These numbers describe the evidence-contract benchmark, not generic insider-threat detection recall.

---

# 23. Adversarial Testing

The detector was repeatedly attacked from different directions.

The adversarial benchmark reached **26 cases**, including:

- baseline attacks
- noisy attacks
- slow attacks
- clock drift
- interleaved activity
- duplicate events
- decoys
- cross-user decoys
- missing telemetry
- partial evidence
- shared-IP collisions
- cross-entity contamination
- simultaneous campaigns
- shared-device/two-user cases
- identity-stage swaps
- 5,000-event benign haystacks

Measured gate:

| Metric | Result |
|---|---:|
| Cases | 26 |
| Benign validated false positives | **0** |
| Validated-incident precision | **100%** |
| Campaign coverage recall | **100%** |
| Campaign coverage FPR | **0%** |

---

# 24. Generalization Testing

Phase 13 included:

- rotated attack structure
- interleaved benign events
- decoy-heavy attacks
- missing device telemetry
- different entity combinations
- simultaneous campaigns
- benign lookalikes
- large benign haystacks

Verified gate:

- malicious validated recall: **100%**
- benign validated FPR: **0%**

---

# 25. Large-Scale Haystack Testing

We explicitly tested:

~~~text
20,000 benign events
+
real attack
~~~

and:

~~~text
20,000 benign events only
~~~

We also tested duplicate attack events and reversed input ordering.

The final robustness gate passed.

---

# 26. Missing Logs

We do not assume missing telemetry means no attack.

~~~text
Complete evidence
    ↓
Validated incident

Incomplete evidence
    ↓
Campaign hypothesis / analyst review

Insufficient or contradictory evidence
    ↓
Silent
~~~

---

# 27. Out-of-Order Logs

Input order is not treated as truth.

Events are evaluated using timestamps and causal relationships.

Therefore an out-of-order input can still become a valid incident if timestamps and entities form a valid chronological chain.

Events that only look correct because they are listed in a particular order are rejected when timestamps contradict the attack.

---

# 28. Clock Drift

A naive system may only use a fixed timestamp threshold.

Our system distinguishes:

- normal bounded correlation
- extended correlation with stronger identity/session evidence

A slow attack cannot simply become valid because we increased the global time window.

A failed global 90-minute-window experiment caused benign slow activity to become a false positive. We rejected that approach and implemented ordered-stage and identity/session-aware handling.

---

# 29. Benign Lookalikes

Example:

~~~text
Authorized login
→ backup file access
→ USB
→ large backup copy
~~~

The system checks authorization signals, identity consistency, entity context, temporal ordering, campaign evidence and contradictory evidence.

Authorized/benign workflows are explicitly included in testing.

---

# 30. Multiple Simultaneous Attacks

The system does not assume there is only one campaign.

Separate user/device/entity contexts can produce separate campaign candidates.

The benchmark includes simultaneous campaigns to verify that Campaign A does not consume Campaign B evidence.

---

# 31. Two Users Sharing One Device

Example:

~~~text
Alice → login → sensitive file

Bob → USB → copy
~~~

A naive system might combine them.

Our system fails closed when explicit cross-user attribution exists inside the reconstruction horizon.

This is a deliberate precision-first decision.

---

# 32. Why Deterministic Core Instead of End-to-End ML?

For this problem, an end-to-end black-box model has disadvantages:

- difficult evidence attribution
- difficult debugging
- difficult judge verification
- difficult reproduction
- difficult false-positive analysis
- difficult handling of missing evidence
- difficult security auditing

Our architecture uses deterministic reasoning for the security-critical gate and AI for explanation.

~~~text
Deterministic security decision
+
AI-assisted investigation
=
Explainable CTI
~~~

---

# 33. Why Not Use an LLM on All Logs?

A language model can infer unsupported relationships, hallucinate evidence, be influenced by malicious log content, struggle with huge log volumes and produce non-reproducible conclusions.

Our architecture prevents this.

The LLM receives only a sealed evidence packet after deterministic validation.

---

# 34. Security Against Prompt Injection in Logs

Security logs are **untrusted data**.

The system therefore treats:

~~~text
logs = data
~~~

not:

~~~text
logs = instructions
~~~

The LLM receives structured evidence and its citations are validated against actual evidence IDs.

---

# 35. Response Generation

After a validated incident, the system produces response recommendations such as:

- isolate endpoint
- investigate account
- revoke suspicious session
- inspect USB/removable-media activity
- preserve evidence
- review sensitive files accessed
- investigate related entities

These are recommendations, not autonomous destructive actions.

---

# 36. Dashboard / Judge Experience

The dashboard exposes:

1. Detection
2. Campaign risk
3. Attack timeline
4. Entity graph
5. Stage-by-stage evidence
6. Deterministic reconstruction
7. Selected evidence
8. Rejected decoys
9. ATT&CK intelligence
10. Response actions
11. Validation status
12. Benign suppression

The judge can inspect why the system reached its conclusion.

---

# 37. Complete Judge Demo

### Demo 1 — Attack

~~~text
Login
→ Sensitive File
→ USB
→ Large Copy
→ Validated Incident
~~~

Show:

- exact event IDs
- timeline
- entity graph
- reconstruction
- ATT&CK
- response

### Demo 2 — Clean

Expected:

~~~text
0 incidents
Suppressed
~~~

### Demo 3 — Adversarial

Show partial attack, reversed order, mismatched entities, slow attack, authorized transfer and benign backup.

Expected:

~~~text
No validated incident
~~~

This proves the system is not simply pattern matching.

---

# 38. End-to-End Data Flow

~~~text
                 SECURITY DATA
                      │
        ┌─────────────┼─────────────┐
        ↓             ↓             ↓
     Windows        Sysmon        Zeek
        │             │             │
        └─────────────┼─────────────┘
                      ↓
                 NORMALIZER
                      ↓
               SecurityEvent
                      ↓
              ENTITY RESOLUTION
                      ↓
             BEHAVIOR SIGNALS
                      ↓
        TEMPORAL + ENTITY CORRELATION
                      ↓
             STAGE CANDIDATES
                      ↓
             EVIDENCE COVERAGE
                      ↓
          CAUSAL RECONSTRUCTION
                      ↓
          CAMPAIGN CONFIDENCE
                      ↓
       ┌──────────────┼──────────────┐
       ↓              ↓              ↓
   INCIDENT       HYPOTHESIS      SILENT
       │              │
       ↓              │
 ATT&CK + RESPONSE    │
       │              │
       └──────┬───────┘
              ↓
     OPTIONAL LLM INVESTIGATOR
              ↓
       GROUNDED EXPLANATION
~~~

---

# 39. What Is Novel About Our Approach?

Our novelty is not simply "we use AI."

The stronger contribution is the combination of:

1. **Evidence-first incident gating** — an incident requires independent evidence across mandatory stages.
2. **Explicit uncertainty** — missing evidence becomes an explicit hypothesis instead of a fabricated incident.
3. **Deterministic causal reconstruction** — selected and rejected evidence are preserved and explainable.
4. **Cross-identity protection** — explicit defense against IP/device/user stitching errors.
5. **Adaptive but bounded temporal reasoning** — drift handling without a giant global search window.
6. **LLM as investigator, not judge** — the generative model cannot create an incident.
7. **Adversarial self-testing** — the detector is tested against benign lookalikes, haystacks, decoys, missing logs and identity collisions.

---

# 40. Why This Is Different From a Rule Engine

A traditional rule might be:

~~~text
IF login
AND file access
AND USB
THEN alert
~~~

Our system asks:

~~~text
Are these the same entity?
Are they causally compatible?
Are they chronologically valid?
Is evidence complete?
Are there contradictory entities?
Are authorization signals present?
Could this be a decoy?
Does the reconstructed path contain exact evidence?
Is campaign confidence sufficient?
~~~

Only then:

~~~text
VALIDATED INCIDENT
~~~

---

# 41. Why This Is Different From a Pure ML Classifier

A classifier might output:

~~~text
Attack probability = 0.94
~~~

But a security analyst still asks:

> Which events prove it?

Our output contains:

~~~text
Stage
→ Evidence IDs
→ Timestamp
→ Entity
→ Relationship
→ Reconstruction
→ ATT&CK
→ Response
~~~

Therefore the output is actionable and auditable.

---

# 42. Limitations

We explicitly acknowledge:

### Dataset coverage
CERT is broader than our current removable-media evidence contract.

### Identity infrastructure
Real production environments need stronger session identity, DHCP/NAT context and endpoint identity.

### Time synchronization
Production deployments should integrate NTP/clock-quality metadata.

### Novel attack types
An attack using completely different evidence types requires additional stage definitions/adapters.

### Scale
Production deployment would require streaming/event-bus infrastructure and optimized correlation indexes.

### LLM dependency
The LLM is optional; explanation quality depends on the configured provider.

These are engineering boundaries, not hidden assumptions.

---

# 43. Production Evolution

A production deployment can evolve to:

~~~text
Endpoint / SIEM
      ↓
Kafka / Event Bus
      ↓
Normalization Layer
      ↓
Feature / Entity Store
      ↓
Streaming Correlation Engine
      ↓
Evidence Graph Store
      ↓
Incident Store
      ↓
SOC Dashboard
      ↓
Optional LLM Investigator
~~~

Additional integrations can include EDR, identity provider, Active Directory, DHCP, VPN, firewall, proxy, cloud audit logs, email security, DLP and SIEM.

---

# 44. Possible Extensions

### Additional exfiltration paths

- HTTP upload
- cloud storage
- email
- FTP/SFTP
- network share
- DNS tunneling

### Additional attack stages

- persistence
- privilege escalation
- lateral movement
- credential access
- command and control
- impact

### Stronger entity resolution

- DHCP history
- NAT mapping
- endpoint UUID
- session identifiers
- AD authentication context

### Streaming detection

Kafka, Redis Streams, Flink or Spark Structured Streaming.

### Graph storage

A graph database for large-scale evidence relationships.

---

# 45. Questions Judges May Ask

## Why not alert on anomaly score?

Because anomaly is only a signal. A benign admin can be anomalous without being malicious. We require a multi-stage evidence chain before validating an incident.

## Why use an LLM if the detector is deterministic?

The LLM is used for investigation and explanation, not security-critical decision-making. This keeps incident creation reproducible and prevents hallucinated evidence.

## What if evidence is missing?

We can create a campaign hypothesis with explicit missing stages, but we do not call it a validated incident.

## What if two users share an IP?

IP is not treated as identity. We use user/device/session context and fail closed when cross-user contamination makes the chain ambiguous.

## What if timestamps are out of order?

Input order is irrelevant. We reason using timestamps and require a valid ordered stage path.

## What if an attack is slow?

We use bounded adaptive temporal reasoning. We do not globally increase the correlation window because that creates look-elsewhere false positives.

## How do you avoid false positives in a huge log stream?

We require multi-stage evidence, entity consistency, temporal validity and reconstruction. We also test large benign haystacks and explicit benign lookalikes.

## What happens when there are decoy events?

The reconstruction searches for a valid ordered stage path and records rejected/decoy evidence separately.

## What dataset did you use?

We use versioned deterministic project scenarios for reproducibility, public security telemetry for ingestion validation, and the CERT Insider Threat Test Dataset r4.2 for raw evidence-contract validation.

## Is your CERT result 4.29% recall?

No. 4.29% is the proportion of the 70 malicious CERT scenarios compatible with our current identity → sensitive file → removable-media evidence contract. It is not detector recall.

## Why doesn't the system detect every CERT attack?

Because the current detector intentionally targets a specific evidence contract. CERT contains many other insider-threat behaviors that require different evidence and stages.

## Why not train a deep learning model?

For the security-critical gate we prioritize auditability, exact evidence attribution and reproducibility. ML can be added as a bounded signal later without allowing it to bypass evidence validation.

## Can the LLM be prompt-injected through logs?

Logs are untrusted data. They are never treated as instructions, and the LLM only receives a structured sealed evidence packet after deterministic validation.

## Can the detector stitch two separate attacks together?

Entity-aware campaign reconstruction, cross-user/device conflict checks and simultaneous-campaign tests are specifically designed to prevent that.

## What is your main novelty?

An evidence-first campaign validation architecture where anomalies are only signals, incomplete evidence becomes explicit hypotheses, deterministic reconstruction selects exact evidence, and the LLM is constrained to investigation rather than incident creation.

---

# 46. 30-Second Explanation

> "Our system is an evidence-first cyber threat intelligence engine. Instead of alerting whenever one log looks suspicious, we normalize heterogeneous security logs and correlate identity, device, file and removable-media evidence. We then reconstruct a temporally valid and entity-consistent attack chain. Only a complete evidence-backed chain becomes a validated incident. If evidence is missing, we produce a campaign hypothesis instead of hallucinating an incident. MITRE ATT&CK provides enrichment, while an optional LLM explains already validated evidence rather than deciding whether an attack occurred."

---

# 47. Technical Explanation

> "The pipeline is adapters → canonical SecurityEvent → behavior signals → temporal/entity correlation → stage candidates → evidence coverage → deterministic causal reconstruction → incident gate. Mandatory stages require exact evidence IDs, temporal validity and entity consistency. Cross-user/device contamination and benign lookalikes are explicitly rejected. The LLM sits after validation and is grounded to a sealed evidence packet."

---

# 48. One-Line Architecture

> **Heterogeneous telemetry → normalized evidence → entity/temporal correlation → causal attack reconstruction → evidence-gated incident → ATT&CK + grounded investigation.**

---

# 49. One-Line Novelty

> **We do not treat anomalies as incidents; we prove incidents by reconstructing an evidence-backed, entity-consistent and temporally valid attack chain.**

---

# 50. Final Answer to the Problem Statement

The problem asks for an AI-powered cyber threat intelligence solution capable of turning heterogeneous security telemetry into useful threat intelligence.

Our answer is a **deterministic evidence-first CTI engine with an optional grounded AI investigator**.

It provides:

- heterogeneous security-log ingestion
- normalization
- entity resolution
- behavior analysis
- temporal correlation
- attack-stage reasoning
- evidence coverage
- causal reconstruction
- campaign confidence
- ATT&CK enrichment
- validated incidents
- incomplete campaign hypotheses
- benign suppression
- exact evidence citations
- attack timelines
- response recommendations
- optional grounded LLM investigation
- adversarial benchmarking
- public-data validation
- raw CERT validation
- reproducible CI gates

The architecture is intentionally designed so that:

~~~text
AI does not replace evidence.
AI works on top of evidence.
~~~

**Evidence first. Explanation second.**

---

# 51. Repository References

Implementation:

~~~text
backend/detector.py
backend/reconstructor.py
backend/models.py
backend/behavior.py
backend/adapters.py
backend/normalizer.py
backend/attack_intel.py
backend/investigator.py
~~~

Reproducible data:

~~~text
backend/data/scenarios.json
backend/data/attack_logs.json
backend/data/clean_logs.json
~~~

Benchmarks:

~~~text
tests/test_phase11_adversarial_benchmark.py
tests/test_phase12_confidence_drift.py
tests/test_phase13_generalization_benchmark.py
tests/test_phase14_final_robustness.py
tests/test_phase15_final_release.py
~~~

Judge material:

~~~text
docs/JUDGE_RUNBOOK.md
~~~

CERT provenance:

~~~text
docs/CERT_RAW_ACQUISITION.md
docs/PHASE8_CERT_RAW_GATE.md
~~~

---

# 52. Final Status

~~~text
Phase 1  Core detection                     ✓
Phase 2  False-positive battle             ✓
Phase 3  Heterogeneous logs                ✓
Phase 4  Behavior                           ✓
Phase 5  ATT&CK                             ✓
Phase 6  Reconstruction                     ✓
Phase 7  Grounded investigator              ✓
Phase 8  Public + raw CERT validation       ✓
Phase 9  Judge demo                         ✓
Phase 10 Evidence coverage                  ✓
Phase 11 Adversarial benchmark              ✓
Phase 12 Confidence + drift                 ✓
Phase 13 Generalization                     ✓
Phase 14 Final robustness                   ✓
Phase 15 Final release gate                 ✓
~~~

**Final engineering principle:**

> # Evidence first, explanation second.
