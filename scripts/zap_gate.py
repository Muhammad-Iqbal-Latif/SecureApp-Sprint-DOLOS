"""Inspect the JSON report produced by OWASP ZAP baseline for high findings."""
import json
from pathlib import Path
import sys
report=Path(sys.argv[1] if len(sys.argv)>1 else 'evidence/zap.json')
if not report.exists():
    raise SystemExit('ZAP report missing; refusing to pass the security gate')
data=json.loads(report.read_text())
alerts=[a for site in data.get('site',[]) for a in site.get('alerts',[])]
block=[a for a in alerts if int(a.get('riskcode',0)) >= 3]
for alert in block: print('BLOCK: ZAP HIGH:',alert.get('alert','unknown'))
print(f'ZAP: {len(alerts)} alerts, {len(block)} high-risk findings')
sys.exit(1 if block else 0)
