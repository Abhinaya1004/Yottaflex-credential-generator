import random, hashlib, json, csv, argparse, shutil
from datetime import datetime, timedelta
from pathlib import Path
SEED=20261022
def mid(p,n,y=None,w=6): return f"{p}-{y}-{n:0{w}d}" if y else f"{p}-{n:0{w}d}"
def h(s): return hashlib.sha256(s.encode()).hexdigest()
def run(full=False):
    random.seed(SEED)
    out=Path("output")
    if out.exists(): shutil.rmtree(out)
    out.mkdir()
    NL=20000 if full else 100
    NC=1000 if full else 10
    NCOMP=15000 if full else 150
    NCRD=10000 if full else 50
    NVER=5000 if full else 20
    learners=[{"learner_id":mid("LRN",i),"name":"Kumar" if i%500==0 else f"Learner_{i}","email":f"learner{i}@yottaflex.test","dob":(datetime(1990,1,1)+timedelta(days=random.randint(0,10000))).date().isoformat(),"effective_from":"2020-01-01"} for i in range(1,NL+1)]
    courses=[{"course_id":f"CRS-{i:04d}","title":f"Course {i}","duration_hours":random.randint(10,120),"effective_from":"2024-01-01"} for i in range(1,NC+1)]
    issuers=[{"issuer_id":f"ISS-{i:03d}","name":f"Academy {i}","effective_from":"2024-01-01"} for i in range(1,6)]
    rules=[{"rule_id":f"RULE-{c['course_id']}","course_id":c['course_id'],"min_score":60,"min_completion_pct":80,"effective_from":"2024-01-01"} for c in courses]
    completions=[];seen=set()
    while len(completions)<NCOMP:
        l=random.choice(learners);c=random.choice(courses);k=(l['learner_id'],c['course_id'])
        if k in seen: continue
        seen.add(k)
        completions.append({"completion_id":f"CMP-{l['learner_id']}-{c['course_id']}","learner_id":l['learner_id'],"course_id":c['course_id'],"score":random.randint(40,100),"completion_pct":random.randint(60,100),"completed_at":(datetime(2025,6,1)+timedelta(days=random.randint(0,300))).isoformat()})
    creds=[];audits=[];revocs=[];ground=[];ac=1;cc=1
    rmap={r['course_id']:r for r in rules}
    for comp in completions:
        if cc>NCRD: break
        r=rmap[comp['course_id']]
        if comp['score']>=r['min_score'] and comp['completion_pct']>=r['min_completion_pct']:
            iss=random.choice(issuers)
            issued=datetime.fromisoformat(comp['completed_at'])+timedelta(days=random.randint(0,5))
            ph=h(f"{comp['learner_id']}|{comp['course_id']}|{issued.isoformat()}|{iss['issuer_id']}")
            cid=mid("CRD",cc,y=2026)
            creds.append({"credential_id":cid,"learner_id":comp['learner_id'],"course_id":comp['course_id'],"completion_id":comp['completion_id'],"issuer_id":iss['issuer_id'],"issued_at":issued.isoformat(),"payload_hash":ph,"status":"active","signature":f"SIG-{ph[:16].upper()}"})
            audits.append({"event_id":f"AUD-{ac:06d}","entity_id":cid,"entity_type":"Credential","action":"ISSUED","timestamp":issued.isoformat(),"actor":iss['issuer_id'],"prev_hash":""});ac+=1;cc+=1
    if len(creds)>=4:
        c0=creds[0];comp0=next(x for x in completions if x['completion_id']==c0['completion_id']);c0['issued_at']=(datetime.fromisoformat(comp0['completed_at'])-timedelta(days=3)).isoformat()
        ground.append({"issue_type":"credential_issued_before_completion","credential_id":c0['credential_id'],"ground_truth_label":"INVALID_ISSUANCE"})
        dup=creds[1].copy();dup['credential_id']=creds[0]['credential_id'];creds.append(dup);ground.append({"issue_type":"duplicate_credential_id","credential_id":dup['credential_id'],"ground_truth_label":"DUPLICATE_ID"})
        c2=creds[2];c2['status']="revoked";revocs.append({"revocation_id":f"REV-{c2['credential_id']}-01","credential_id":c2['credential_id'],"reason":"academic_integrity","revoked_at":datetime.now().isoformat(),"revoked_by":"ISS-001"});ground.append({"issue_type":"revoked_credential_verifies_as_active","credential_id":c2['credential_id'],"ground_truth_label":"SHOULD_FAIL_VERIFICATION"})
        c3=creds[3];c3['payload_hash']="0"*64;ground.append({"issue_type":"altered_payload_hash_not_detected","credential_id":c3['credential_id'],"ground_truth_label":"TAMPERED_HASH"})
    vers=[]
    for i in range(1,NVER+1):
        cr=random.choice(creds);bad=any(r['credential_id']==cr['credential_id'] for r in revocs) or cr['payload_hash']=="0"*64;res="failed" if bad else "verified"
        vers.append({"verification_id":mid("VER",i,y=2026),"credential_id":cr['credential_id'],"requested_at":datetime.now().isoformat(),"result":res,"expected_result":res,"verifier_id":"VERIFIER-001"})
        audits.append({"event_id":f"AUD-{ac:06d}","entity_id":cr['credential_id'],"entity_type":"VerificationRequest","action":res.upper(),"timestamp":datetime.now().isoformat(),"actor":"VERIFIER-001","prev_hash":""});ac+=1
    def wc(n,d):
        with open(out/f"{n}.csv","w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=d[0].keys());w.writeheader();w.writerows(d)
    wc("learners",learners);wc("courses",courses);wc("issuers",issuers);wc("credential_rules",rules);wc("completion_records",completions);wc("credentials",creds);wc("verification_requests",vers);wc("revocations",revocs);wc("audit_events",audits)
    json.dump(ground,open(out/"ground_truth.json","w"),indent=2)
    chk=h(open(out/"credentials.csv","rb").read().decode());json.dump({"seed":SEED,"checksum":chk[:16],"counts":{"learners":len(learners),"courses":len(courses),"credentials":len(creds)},"anomalies":len(ground)},open(out/"validation_summary.json","w"),indent=2)
    json.dump({"source":"synthetic","seed":SEED},open(out/"source_manifest.json","w"),indent=2)
    print(f"DONE {len(creds)} {chk[:16]}")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--full",action="store_true");p.add_argument("--demo",action="store_true");a=p.parse_args();run(full=a.full)