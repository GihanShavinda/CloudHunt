from __future__ import annotations
import os, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
os.environ.setdefault('CLOUDHUNT_DATABASE_URL','')
os.environ.setdefault('CLOUDHUNT_REDIS_URL','')
from cloudhunt.api.casestore import build_demo_service

def main():
    svc=build_demo_service(); ids=list(svc.entries)
    if not ids:
        print('No demo case was produced.'); return 1
    detail=svc.get_case(ids[0])
    print('=== CLOUDHUNT FINAL OFFLINE DEMO ===')
    print(f"Case: {detail['case_id']} — {detail['title']}")
    print(f"Blast radius: {detail['blast']['score']}")
    print('Attack chain:')
    for s in detail['chain']: print(f"  {s['order']}. {s['actor'].split('/')[-1]} -> {s['action']} [{s['attack_id'] or '-'}]")
    print('Detections:')
    for d in detail['detections']: print(f"  - {d['key']} ({d['layer']}) conf={d['confidence']:.2f}")
    print('ATT&CK:')
    for tactic, tids in detail['attack_map'].items(): print(f"  - {tactic}: {', '.join(tids)}")
    print('Recommended actions:')
    for a in detail['recommended_actions']: print(f"  - {a['action_key']}: {a['status']} ({a['mode']})")
    print('No real AWS credentials were used.')
    return 0
if __name__=='__main__': raise SystemExit(main())
