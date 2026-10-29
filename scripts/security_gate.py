"""Enforce high/critical finding policy on machine-readable scanner output."""
import argparse
import json
from pathlib import Path
import sys
p=argparse.ArgumentParser()
p.add_argument('--input',required=True)
args=p.parse_args()
findings=json.loads(Path(args.input).read_text())
blocked=[f for f in findings if f.get('severity','').upper() in ('HIGH','CRITICAL') and f.get('status','open').lower()=='open']
for f in blocked:print(f'BLOCK: {f.get("severity")}: {f.get("id")} - {f.get("title")}')
print(f'Security gate: {len(blocked)} blocking findings / {len(findings)} total')
sys.exit(1 if blocked else 0)
