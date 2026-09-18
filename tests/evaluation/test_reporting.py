from evaluation.reporting import write_reports

def test_reports_created(tmp_path):
    summary={'scenarios_failed':0,'scenarios_passed':1,'scenarios_total':1,'safety_violations':0}
    row={'scenario':'x','passed':True,'duration_ms':1,'precision':1,'recall':1,'f1':1,'false_positive_rate':0,'correlation_score':1,'privesc_path_score':1,'chain_accuracy':1,'safety_violations':0,'attack_ids':['T1']}
    write_reports(tmp_path,summary,[row])
    for n in ('evaluation.json','evaluation.csv','evaluation.html','attack_coverage.json'): assert (tmp_path/n).exists()
