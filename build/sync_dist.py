"""Regenerate dist/index.html from the canonical UI_HTML constant."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reversesuite import api  # noqa: E402


def main() -> int:
    target = ROOT / "dist" / "index.html"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(api.UI_HTML, encoding="utf-8", newline="")
    print("wrote %s (%d bytes)" % (target, len(api.UI_HTML)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())