from __future__ import annotations
import csv, html, json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

def write_reports(report_dir: Path, summary: dict, results: list[dict]) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    payload={'generated_at':datetime.now(timezone.utc).isoformat(),'summary':summary,'scenarios':results}
    (report_dir/'evaluation.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    fields=['scenario','passed','duration_ms','precision','recall','f1','false_positive_rate','correlation_score','privesc_path_score','chain_accuracy','safety_violations']
    with (report_dir/'evaluation.csv').open('w',newline='',encoding='utf-8') as f:
        wr=csv.DictWriter(f,fieldnames=fields); wr.writeheader();
        for r in results: wr.writerow({k:r.get(k) for k in fields})
    rows=''.join(f"<tr><td>{html.escape(r['scenario'])}</td><td class={'ok' if r['passed'] else 'bad'}>{'PASS' if r['passed'] else 'FAIL'}</td><td>{r['precision']:.3f}</td><td>{r['recall']:.3f}</td><td>{r['f1']:.3f}</td><td>{r['correlation_score']:.3f}</td><td>{r['chain_accuracy']:.3f}</td><td>{r['safety_violations']}</td></tr>" for r in results)
    page=f"""<!doctype html><html><head><meta charset="utf-8"><title>CloudHunt Evaluation</title><style>body{{font-family:Inter,Segoe UI,sans-serif;background:#020907;color:#edfff6;padding:32px}}.card{{background:#081a13;border:1px solid rgba(65,255,157,.2);border-radius:14px;padding:20px;margin-bottom:18px}}h1{{color:#36ff93}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #17382c;text-align:left}}th{{color:#86b5a3}}.ok{{color:#36ff93;font-weight:800}}.bad{{color:#ff5d78;font-weight:800}}code{{color:#34d9ff}}</style></head><body><h1>CloudHunt Final Evaluation</h1><div class="card"><b>Overall:</b> {'PASS' if summary['scenarios_failed']==0 and summary['safety_violations']==0 else 'FAIL'} · Passed {summary['scenarios_passed']}/{summary['scenarios_total']} · Safety violations {summary['safety_violations']}</div><div class="card"><table><thead><tr><th>Scenario</th><th>Status</th><th>Precision</th><th>Recall</th><th>F1</th><th>Correlation</th><th>Chain</th><th>Safety</th></tr></thead><tbody>{rows}</tbody></table></div></body></html>"""
    (report_dir/'evaluation.html').write_text(page,encoding='utf-8')
    coverage=defaultdict(lambda:{'technique_id':'','technique_name':'','scenarios':set(),'number_of_detections':0})
    for r in results:
        for tid in r.get('attack_ids',[]):
            row=coverage[tid]; row['technique_id']=tid; row['technique_name']=tid; row['scenarios'].add(r['scenario']); row['number_of_detections']+=1
    out=[]
    for tid,row in sorted(coverage.items()): row['scenarios']=sorted(row['scenarios']); out.append(row)
    (report_dir/'attack_coverage.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
