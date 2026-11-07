"""PyInstaller entry point: absolute import (frozen scripts have no package)."""
from reversesuite.cli import main

if __name__ == "__main__":
    raise SystemExit(main())