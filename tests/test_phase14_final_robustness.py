import json
from datetime import timedelta
from pathlib import Path
from backend.detector import analyze
from backend.models import SecurityEvent
ROOT=Path(__file__).resolve().parents[1]
SCENARIOS=ROOT/"backend/data/scenarios.json"
def load():
 raw=json.loads(SCENARIOS.read_text()); return {k:[SecurityEvent.model_validate(x) for x in v] for k,v in raw.items()}
def clone(es): return [SecurityEvent.model_validate(e.model_dump()) for e in es]
def disposition(r):
 if r.correlated_incidents:return "validated"
 if r.campaign_hypotheses:return "hypothesis"
 if r.watchlist_candidates:return "watchlist"
 return "suppressed"
def stress_stream(base):
 attack=clone(base); anchor=attack[0].timestamp; stream=[]
 # 20k benign events across unrelated identities/devices.
 for i in range(20000):
  stream.append(SecurityEvent(event_id=f"STRESS-{i}",timestamp=anchor+timedelta(seconds=i%3600),event_type="process_start",user=f"u{i%200}",device=f"D{i%100}",src_ip=f"10.20.{i%250}.{(i%240)+1}",application="office",source="endpoint",metadata={"benign_fixture":True}))
 # Interleave the real campaign, duplicate a few events, and reverse input order.
 stream.extend(attack)
 stream.extend(clone(attack[:2]))
 return list(reversed(stream))
def test_phase14_final_robustness_gate():
 s=load();
 cases=[
  ("large_haystack",stress_stream(s["full_attack"]),"validated",True),
  ("clean_haystack",[SecurityEvent(event_id=f"CLEAN-{i}",timestamp=s["clean"][0].timestamp+timedelta(seconds=i%3600),event_type="process_start",user=f"clean{i%100}",device=f"CD{i%50}",src_ip=f"192.0.2.{(i%250)+1}",application="office",source="endpoint",metadata={"benign_fixture":True}) for i in range(20000)],"suppressed",False),
  ("baseline_replay",clone(s["full_attack"]),"validated",True),
  ("benign_backup",clone(s["benign_backup"]),"suppressed",False),
 ]
 obs=[]
 for name,events,expected,malicious in cases:
  r=analyze(events); obs.append({"case":name,"expected":expected,"actual":disposition(r),"malicious":malicious,"incidents":r.correlated_incidents,"hypotheses":len(r.campaign_hypotheses)})
 recall=sum(o["malicious"] and o["actual"]=="validated" for o in obs)/sum(o["malicious"] for o in obs)
 fpr=sum((not o["malicious"]) and o["actual"]=="validated" for o in obs)/sum(not o["malicious"] for o in obs)
 assert recall==1.0,obs
 assert fpr==0.0,obs
 assert all(o["actual"] in {"validated","hypothesis","watchlist","suppressed"} for o in obs)
