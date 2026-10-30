"""Conservative AST-based security gate; exit nonzero on verified unsafe code patterns.
Scan deployment code only; isolated intentionally vulnerable teaching labs scanned separately.
"""
import ast
from pathlib import Path
import sys

FILES=[*Path('dolos').glob('*.py'),Path('run.py')]
issues=[]
for file in FILES:
    tree=ast.parse(file.read_text(),filename=str(file))
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call):continue
        name=ast.unparse(node.func)
        if name in ('eval','exec','os.system','os.popen'):
            issues.append(f'HIGH {file}:{node.lineno}: {name} forbidden')
        if name.endswith(('.run','.Popen','.call','.check_output')) and any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords):
            issues.append(f'CRITICAL {file}:{node.lineno}: shell=True forbidden')
        if name=='pickle.loads':
            issues.append(f'HIGH {file}:{node.lineno}: unsafe deserialization')
for issue in issues:print(issue)
print(f'SAST gate: {len(issues)} high/critical deployment findings; {len(FILES)} Python files scanned')
sys.exit(1 if issues else 0)
