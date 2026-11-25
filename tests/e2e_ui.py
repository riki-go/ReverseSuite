"""End-to-end UI test: drives the real interface in headless Chromium.

The desktop shell is a thin Tauri wrapper around this page, so exercising the page
covers the analyse / diff / graph flows. Run it on demand:

    python tests/e2e_ui.py

Requires `pip install playwright` + `playwright install chromium` (the CI python job
does not install them, so this test is opt-in).
"""
from __future__ import annotations

import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
FIXTURES = ROOT / "fixtures"


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("SKIP playwright is not installed (pip install playwright)")
        return 0

    from reversesuite import api

    server, token, _thread = api.serve(None)
    port = server.server_address[1]
    failures = []

    def check(name, condition, detail=""):
        print(("PASS " if condition else "FAIL ") + name + (" :: " + detail if detail and not condition else ""))
        if not condition:
            failures.append(name)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.add_init_script("window.__rs_token = %r;" % token)
            page.goto("http://127.0.0.1:%d/" % port)
            page.wait_for_selector("#status")

            def wait_text(selector, needle, timeout=60):
                deadline = time.time() + timeout
                seen = ""
                while time.time() < deadline:
                    seen = page.inner_text(selector)
                    if needle in seen:
                        return True, seen
                    page.wait_for_timeout(250)
                return False, seen

            check("ui loads with token", page.inner_text("#status").strip().lower() == "connected",
                  page.inner_text("#status"))

            page.fill("#path", str(FIXTURES / "frozen" / "a.exe"))
            page.click("#run")
            ok, out = wait_text("#out", "findings")
            check("analyse PE", ok and "status: ok" in out and "functions:" in out, out[:160])

            page.click("#gcall")
            ok, state = wait_text("#gstate", "nodes", 30)
            check("native graph renders", ok and "edges" in state, state[:120])

            page.fill("#left", str(FIXTURES / "frozen" / "b.exe"))
            page.fill("#right", str(FIXTURES / "frozen" / "a.exe"))
            page.click("#diff")
            ok, summary = wait_text("#summary", "nodes")
            check("diff produces a summary", ok and "+" in summary, summary[:160])

            page.fill("#left", "")
            page.fill("#right", "")
            page.click("#diff")
            ok, guard = wait_text("#diffstate", "Enter both files", 10)
            check("empty diff guard", ok, guard[:120])

            page.fill("#path", str(FIXTURES / "multi" / "demo.apk"))
            page.click("#run")
            ok, out = wait_text("#out", "dex graph")
            check("apk analysis reports dex graph", ok, out[:160])
            page.click("#gdex")
            ok, state = wait_text("#gstate", "dex:", 30)
            check("dex graph renders", ok and "methods" in state, state[:120])

            browser.close()
    finally:
        server.shutdown()
        server.server_close()

    if failures:
        print("FAILED: " + ", ".join(failures))
        return 1
    print("all ui checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
