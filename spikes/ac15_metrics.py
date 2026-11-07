import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from reversesuite import loader, functions
proj = pathlib.Path(__file__).resolve().parents[1]
truth = json.loads((proj / "fixtures/out/truth_b.json").read_text(encoding="utf-8"))
truth_addrs = {t["addr"] for t in truth}
data = (proj / "fixtures/frozen/b.exe").read_bytes()
text = loader.text_bytes(data)
entry = functions.entry_point(data)
found = functions.discover(text, entry=entry)
found_addrs = {f.start for f in found}
matched = truth_addrs & found_addrs
recall = len(matched) / len(truth_addrs) if truth_addrs else 0
precision = len(matched) / len(found_addrs) if found_addrs else 0
print(json.dumps({"entry": hex(entry) if entry else None,
                  "truth": len(truth_addrs), "found": len(found_addrs), "matched": len(matched),
                  "recall": round(recall, 4), "precision": round(precision, 4),
                  "missed": sorted(truth_addrs - found_addrs),
                  "extra": sorted(found_addrs - truth_addrs)[:10]}, indent=1))