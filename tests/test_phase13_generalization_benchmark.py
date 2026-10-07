import json
from datetime import timedelta
from pathlib import Path
from backend.detector import analyze
from backend.models import SecurityEvent
ROOT=Path(__file__).resolve().parents[1]
RESULTS=ROOT/"docs/results/phase13_generalization.json"
SCENARIOS=ROOT/"backend/data/scenarios.json"
def load():
 raw=json.loads(SCENARIOS.read_text()); return {k:[SecurityEvent.model_validate(x) for x in v] for k,v in raw.items()}
def clone(es): return [SecurityEvent.model_validate(e.model_dump()) for e in es]
def disp(r):
 if r.correlated_incidents:return "validated"
 if r.campaign_hypotheses:return "hypothesis"
 if r.watchlist_candidates:return "watchlist"
 return "suppressed"
def rotate_attack(base):
 es=clone(base); anchor=es[0].timestamp
 for i,e in enumerate(es): e.timestamp=anchor+timedelta(minutes=[0,3,7,8,11][i])
 # unseen resource/application identities
 for e in es: e.application=f"svc-{e.application}"; e.src_ip="203.0.113.77"
 return es
def interleave(base):
 es=clone(base); anchor=es[0].timestamp
 noise=[]
 for i,m in enumerate([1,4,6,9,10]):
  noise.append(SecurityEvent(event_id=f"UNSEEN-N-{i}",timestamp=anchor+timedelta(minutes=m),event_type="process_start",user="benign",device="DEV-B",src_ip="10.9.0.2",application="backup",source="endpoint",metadata={"benign_fixture":True}))
 return sorted(es+noise,key=lambda e:e.timestamp)
def decoys(base):
 es=clone(base); anchor=es[0].timestamp
 for i,m in enumerate([2,5,6,9,10,12,14]):
  es.append(SecurityEvent(event_id=f"DECOY-{i}",timestamp=anchor+timedelta(minutes=m),event_type="file_access" if i%2 else "usb_mount",user="alice",device="DEV-07",src_ip="10.0.0.9",application="decoy",source="endpoint",metadata={"sensitive":i%2==1,"removable":i%2==0}))
 return sorted(es,key=lambda e:e.timestamp)
def missing_noise(base):
 es=clone(base); es=[e for e in es if e.event_type!="device_enroll"]
 for e in es: e.metadata={**e.metadata,"collector":"sensor-v2"}
 return es
def simultaneous(base):
 a=clone(base); b=clone(base)
 for e in b: e.event_id="B-"+e.event_id; e.user="bob"; e.device="DEV-88"; e.src_ip="198.51.100.9"
 return sorted(a+b,key=lambda e:e.timestamp)
def benign_lookalike():
 return [SecurityEvent(event_id=f"LOOK-{i}",timestamp=SecurityEvent.model_validate(load()["benign_backup"][0].model_dump()).timestamp+timedelta(minutes=i),event_type=t,user="ivy",device="DEV-21",src_ip="10.0.0.21",application="backup",source="endpoint",metadata=m) for i,(t,m) in enumerate([("login",{"unusual_ip":False}),("file_access",{"sensitive":True}),("usb_mount",{"removable":True}),("file_copy",{"bytes":2400000000,"destination":"USB-21"})])]
def test_phase13_generalization_gate():
 s=load(); cases=[
 ("rotated_structure",rotate_attack(s["full_attack"]),"validated",True),
 ("interleaved_benign",interleave(s["full_attack"]),"validated",True),
 ("decoy_heavy",decoys(s["full_attack"]),"validated",True),
 ("missing_device_enroll",missing_noise(s["full_attack"]),"validated",True),
 ("simultaneous_campaigns",simultaneous(s["full_attack"]),"validated",True),
 ("benign_lookalike",benign_lookalike(),"suppressed",False),
 ("benign_haystack",s["clean"]+interleave(s["benign_backup"])*100,"suppressed",False),
 ]
 obs=[]
 for name,es,expected,mal in cases:
  r=analyze(es); obs.append({"case":name,"expected":expected,"actual":disp(r),"malicious":mal,"incidents":r.correlated_incidents,"hypotheses":len(r.campaign_hypotheses)})
 tp=sum(o["malicious"] and o["actual"]=="validated" for o in obs); fp=sum((not o["malicious"]) and o["actual"]=="validated" for o in obs)
 recall=tp/sum(o["malicious"] for o in obs); fpr=fp/sum(not o["malicious"] for o in obs)
 report={"experiment":"Phase 13 unseen/generalization benchmark","metrics":{"cases":len(obs),"validated_recall":round(recall,4),"validated_fpr":round(fpr,4)},"observations":obs}
 RESULTS.parent.mkdir(parents=True,exist_ok=True); RESULTS.write_text(json.dumps(report,indent=2)+"\n")
 assert recall==1.0,obs
 assert fpr==0.0,obs
 assert all(o["actual"] in {"validated","hypothesis","watchlist","suppressed"} for o in obs)
