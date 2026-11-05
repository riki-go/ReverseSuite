import json, subprocess, sys, pathlib
proj = pathlib.Path(r"D:\OpenClaw\workspace\projects\reversesuite")
man = json.loads((proj/'fixtures'/'corrupt-manifest.json').read_text(encoding='utf-8-sig'))
rows = []
ok = True
for case in man["cases"]:
    p = proj/"fixtures"/"out"/"corrupt"/case["file"]
    r = subprocess.run([sys.executable, "-m", "reversesuite", "analyze", str(p), "--json"],
                       capture_output=True, cwd=str(proj/"src"))
    got_status = "unknown"
    try:
        got_status = json.loads(r.stdout.decode("utf-8"))["status"]
    except Exception:
        pass
    match = (got_status == case["expected_status"] and r.returncode == case["expected_exit_code"])
    ok = ok and match
    code = ""
    try:
        code = json.loads(r.stdout.decode("utf-8"))["diagnostics"][0]["code"]
    except Exception:
        pass
    rows.append((case["id"], case["expected_status"], case["expected_exit_code"], got_status, r.returncode, code, match))
for row in rows:
    print("%-3s exp=%-8s/%d got=%-8s/%d code=%-24s %s" % row)
print("ALL_MATCH=" + str(ok))