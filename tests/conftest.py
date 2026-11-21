"""Configuration commune : les modules du projet s'importent "a plat" depuis leurs dossiers."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for folder in ("", "collector", "vulnerability", "agent"):
    path = str(ROOT / folder)
    if path not in sys.path:
        sys.path.insert(0, path)
