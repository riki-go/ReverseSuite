import json, pathlib, sys
sys.path.insert(0, r"D:\OpenClaw\workspace\projects\reversesuite\src")
from reversesuite import loader, functions
proj = pathlib.Path(r"D:\OpenClaw\workspace\projects\reversesuite")
truth = json.loads((proj/'fixtures/out/truth_b.json').read_text(encoding='utf-8'))
truth_addrs = {t['addr'] for t in truth}
data = (proj/'fixtures/frozen/b.exe').read_bytes()
text = loader.text_bytes(data)
found = functions.discover(text)
found_addrs = {f.start for f in found}
matched = truth_addrs & found_addrs
recall = len(matched)/len(truth_addrs) if truth_addrs else 0
precision = len(matched)/len(found_addrs) if found_addrs else 0
print(json.dumps({'truth': len(truth_addrs), 'found': len(found_addrs), 'matched': len(matched),
                  'recall': round(recall,3), 'precision': round(precision,3),
                  'missed': sorted(truth_addrs - found_addrs)[:10]}, indent=1))