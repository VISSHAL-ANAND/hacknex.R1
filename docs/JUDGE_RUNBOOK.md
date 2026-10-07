# Judge Demo Runbook — HNX26PSI03

## Objective

Demonstrate one complete attack reconstruction and immediately prove that the engine does **not** confuse anomalies, partial evidence, or benign lookalikes with validated incidents.

Core message:

> **Evidence first, explanation second.**

The deterministic engine decides whether an incident is valid. ATT&CK explains validated behavior. The optional LLM investigator does not create incidents.

## 3-minute judge flow

### 1. Open the console

Run locally:

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000`.

The first screen should show the Evidence-First Attack Reconstruction console and the Phase 2 validation status.

### 2. Trigger the full attack

Click **Run Judge Demo**.

Expected result:

- **VALIDATED INCIDENT**
- non-zero campaign risk
- complete timeline
- three mandatory attack stages with evidence
- entity graph
- deterministic reconstruction
- selected event IDs
- rejected decoys, when present
- ATT&CK enrichment
- response actions

The demo attack is:

```
Unusual Login
  → New Device
  → Sensitive File Access
  → USB / Removable Media
  → Large Copy to USB
  → Validated Incident
```

### 3. Point at the proof, not the score

Show the judge:

1. **Timeline** — events are ordered by timestamp.
2. **Campaign Risk** — campaign confidence is separate from event anomaly.
3. **Entity Graph** — user/device/IP/resource continuity.
4. **Attack Stages & Evidence** — every mandatory stage has real event IDs.
5. **Deterministic Reconstruction** — causal edges explain why events were selected.
6. **Decoys Rejected** — candidate noise does not automatically become evidence.
7. **ATT&CK Intelligence** — enrichment is attached after validation.
8. **Recommended Response** — response is tied to the validated incident.

Do not claim that a high anomaly score alone creates an incident.

## 4. Prove benign suppression

Click **Run Clean**.

Expected result:

- **NO INCIDENT VALIDATED**
- **BENIGN / SUPPRESSED**
- no causal incident graph
- no ATT&CK incident enrichment
- no response actions

Say:

> “The system is intentionally silent because isolated suspicious-looking events do not satisfy the complete evidence contract.”

## 5. Show adversarial behavior

Use **Scenario Lab**.

Recommended order:

| Scenario | Expected | Judge point |
|---|---|---|
| `partial_attack` | Campaign hypothesis / no validated incident | Missing evidence does not cross incident boundary |
| `mismatched_entities` | Suppressed | Entity stitching cannot manufacture a campaign |
| `reversed_order` | Suppressed | Temporal contradiction fails closed |
| `slow_attack` | Suppressed | Large time gaps do not become incidents merely by widening the window |
| `shared_ip_collision` | Suppressed | Shared IP is not identity |
| `authorized_transfer` | Suppressed | Authorized activity is not automatically malicious |
| `benign_backup` | Suppressed | Benign high-volume behavior remains silent |

If time is limited, show **partial_attack → mismatched_entities → authorized_transfer**.

## 6. Explain the novelty

Use this sequence:

1. **Anomaly is not an incident.**
2. **Incomplete evidence becomes a hypothesis, not a false-confidence incident.**
3. **Cross-identity/device contamination fails closed.**
4. **Temporal drift is handled adaptively only when strong causal/entity continuity exists.**
5. **Decoys are explicitly rejected during deterministic reconstruction.**
6. **ATT&CK and LLM explanation happen after evidence validation.**
7. **Every claim is regression-gated by adversarial and unseen-attack benchmarks.**

## 7. What is actually validated

The project has completed Phase 1–15 engineering gates.

Key measured claims:

- Phase 2: 0 false positives and 0 missed validated attacks in the controlled benchmark.
- Phase 11: adversarial benchmark includes noisy, slow, decoy, identity-collision, cross-user/device, simultaneous-campaign and 5,000-event haystack cases.
- Phase 12: confidence/drift benchmark prevents naive global temporal-window widening and validates bounded temporal drift.
- Phase 13: unseen/generalization benchmark achieved 100% validated malicious recall and 0% validated benign FPR on its defined benchmark.
- Phase 14: 20,000-event haystack stress passed for both attack and benign controls.
- Phase 15: final targeted regression, full pytest and frontend syntax gate passed.

### CERT wording

Do **not** say “CERT recall is 4.29%.”

Correct wording:

> “The raw CERT benchmark contained 70 malicious scenarios; 3 matched the project's current identity → sensitive-file → removable-media evidence contract. All 3 compatible scenarios completed the ordered chain. The 4.29% figure is compatibility coverage, not end-to-end detector recall.”

The Raw CERT workflow is intentionally separate from ordinary PR CI because it depends on externally acquired raw data and the official answer key.

## Judge questions and safe answers

### “Is this just anomaly detection?”

No. Anomaly signals are inputs. A validated incident requires a coherent multi-stage chain with temporal and entity consistency and evidence IDs.

### “Can the LLM hallucinate an incident?”

Not at the validation boundary. The LLM investigator only runs after deterministic validation and must cite real event IDs. Missing provider configuration fails closed.

### “What happens when logs are missing?”

The system can surface a campaign hypothesis when supported, but it does not lower the incident gate. Missing mandatory evidence cannot become a validated incident.

### “What about attackers who spread actions out?”

The system does not simply expand the global window. Phase 12 introduced bounded temporal drift with strong causal/entity continuity while preserving slow benign suppression.

### “What about shared IPs?”

IP alone is not identity. Entity consistency and cross-user/device conflict checks prevent unrelated users from being stitched into one campaign.

### “How do you avoid looking only at your own attack?”

Phase 13 constructs malicious campaigns independently from the known demo fixture. It uses different users, devices, applications, resources, timing and session patterns, plus decoy and simultaneous-campaign cases. The benchmark is intentionally limited to the declared removable-media evidence contract rather than claiming universal unseen-attack recall.

### “Is this production-grade recall?”

Do not claim that. The defensible claim is that the implemented evidence-first contract is reproducible and regression-gated on the measured benchmarks.

## Final pre-demo checklist

- [ ] `main` is the demo branch.
- [ ] `python -m pytest -q` passes.
- [ ] `node --check frontend/app.js` passes.
- [ ] `GET /health` returns `status=ok`.
- [ ] Full attack produces a validated incident.
- [ ] Clean scenario remains silent.
- [ ] Partial attack does not become a validated incident.
- [ ] Entity mismatch remains silent.
- [ ] Authorized transfer remains silent.
- [ ] No detector changes are introduced during the presentation.

## One-line pitch

> **“We don't alert because one event looks suspicious; we validate an attack only when independent evidence forms a coherent, entity-consistent, temporally valid chain — and we show the exact events that prove it.”**
