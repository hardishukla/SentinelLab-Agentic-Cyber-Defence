"""Offline CLI demonstration: python run_demo.py"""
from pathlib import Path
import json
from sentinel import parse_events, triage, evaluate
ROOT=Path(__file__).parent
df=parse_events(ROOT / 'data' / 'synthetic_soc_events.csv')
results=triage(df)
metrics=evaluate(df,results)
print(f"SentinelLab demo: {len(df)} synthetic events, {len(results['alerts'])} alerts, {len(results['cases'])} cases")
print('Evaluation on this labeled sample only:',metrics)
for a in results['alerts']:
    print(f"[{a['severity']}] {a['type']} | evidence={','.join(a['evidence_event_ids'])}")
(ROOT / 'data' / 'demo_results.json').write_text(json.dumps({'results':results,'metrics':metrics},indent=2),encoding='utf-8')
print('Saved data/demo_results.json')
