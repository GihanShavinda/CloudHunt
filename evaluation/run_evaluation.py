from __future__ import annotations
import argparse, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT/'src'):
    if str(p) not in sys.path: sys.path.insert(0,str(p))
from evaluation.harness.evaluator import Evaluator
from evaluation.metrics.detection_metrics import binary_metrics
from evaluation.models import EvaluationSummary
from evaluation.reporting import write_reports
from evaluation.scenarios.registry import SCENARIOS

def main():
    ap=argparse.ArgumentParser(description='CloudHunt final evaluation')
    ap.add_argument('--scenario',choices=sorted(SCENARIOS))
    ap.add_argument('--all',action='store_true',help='run all scenarios (default)')
    args=ap.parse_args()
    selected=[args.scenario] if args.scenario else list(SCENARIOS)
    ev=Evaluator(ROOT); t0=time.perf_counter(); results=[]
    for sid in selected:
        r=ev.run(sid,SCENARIOS[sid]); results.append(r)
        print(f"[{'PASS' if r.passed else 'FAIL'}] {sid:24} precision={r.precision:.2f} recall={r.recall:.2f} correlation={r.correlation_score:.2f} chain={r.chain_accuracy:.2f}")
    expected=[SCENARIOS[r.scenario]['attack'] for r in results]
    predicted=[bool(r.detections_actual) for r in results]
    bm=binary_metrics(expected,predicted)
    attacks=[r for r in results if SCENARIOS[r.scenario]['attack']]
    summary=EvaluationSummary(
        scenarios_total=len(results), scenarios_passed=sum(r.passed for r in results), scenarios_failed=sum(not r.passed for r in results),
        overall_precision=bm.precision, overall_recall=bm.recall, overall_f1=bm.f1, overall_fpr=bm.false_positive_rate,
        average_chain_accuracy=sum(r.chain_accuracy for r in attacks)/len(attacks) if attacks else 0.0,
        average_privesc_accuracy=max((r.privesc_path_score for r in results),default=0.0),
        average_correlation_accuracy=sum(r.correlation_score for r in attacks)/len(attacks) if attacks else 0.0,
        safety_violations=sum(r.safety_violations for r in results), total_runtime_ms=round((time.perf_counter()-t0)*1000,3))
    write_reports(ROOT/'evaluation'/'reports',summary.to_dict(),[r.to_dict() for r in results])
    print('\n============================================================')
    print('CLOUDHUNT FINAL EVALUATION')
    print('============================================================')
    print(f"Scenarios passed:          {summary.scenarios_passed}/{summary.scenarios_total}")
    print(f"Overall precision:         {summary.overall_precision:.3f}")
    print(f"Overall recall:            {summary.overall_recall:.3f}")
    print(f"Overall F1:                {summary.overall_f1:.3f}")
    print(f"False positive rate:       {summary.overall_fpr:.3f}")
    print(f"Correlation accuracy:      {summary.average_correlation_accuracy:.3f}")
    print(f"Chain accuracy:            {summary.average_chain_accuracy:.3f}")
    print(f"Privesc path accuracy:     {summary.average_privesc_accuracy:.3f}")
    print(f"Unsafe automatic actions:  {summary.safety_violations}")
    print(f"RESULT: {'PASS' if summary.scenarios_failed==0 and summary.safety_violations==0 else 'FAIL'}")
    return 0 if summary.safety_violations==0 else 2
if __name__=='__main__': raise SystemExit(main())
