from __future__ import annotations

import ast
import hashlib
import json
import random
from pathlib import Path

MAX_FILES = 1500
MIN_BYTES = 500
MAX_BYTES = 50_000

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "data" / "raw" / "benign_real"
MANIFEST = ROOT / "data" / "splits" / "benign_real_manifest.jsonl"

import sys as _sys
ROOTS_TO_SCAN = [
    Path(_sys.prefix) / "lib" / f"python{_sys.version_info.major}.{_sys.version_info.minor}",
    Path(_sys.prefix) / "lib" / f"python{_sys.version_info.major}.{_sys.version_info.minor}" / "site-packages",
    Path("/usr/lib/python3"),
    Path("/usr/lib/python3/dist-packages"),
]
EXCLUDE_DIR_PARTS = {"tests", "test", "__pycache__", "_test", "testing"}

def _is_acceptable(path: Path) -> bool:
    if any(part in EXCLUDE_DIR_PARTS for part in path.parts):
        return False
    name = path.name
    if name.startswith("test_") or name.endswith("_test.py"):
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size < MIN_BYTES or size > MAX_BYTES:
        return False
    return True

def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)

    seen_hashes: set[str] = set()
    candidates: list[Path] = []
    for root in ROOTS_TO_SCAN:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if _is_acceptable(path):
                candidates.append(path)
    print(f"scanned {sum(1 for _ in candidates)} candidate files")

    rng = random.Random(7)
    rng.shuffle(candidates)

    records = []
    for path in candidates:
        if len(records) >= MAX_FILES:
            break
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        h = hashlib.sha1(text.encode("utf-8")).hexdigest()
        if h in seen_hashes:
            continue
        try:
            ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        seen_hashes.add(h)
        rec_id = f"benign_real_{len(records):05d}"
        out_path = OUT_DIR / f"{rec_id}.py"
        out_path.write_text(text)
        records.append({
            "id": rec_id,
            "path": str(out_path),
            "label": 0,
            "label_name": "benign",
            "template": f"stdlib::{path.parts[-3] if len(path.parts) >= 3 else path.name}",
            "obfuscation": None,
            "source": "real_benign",
        })

    with MANIFEST.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} real benign scripts to {OUT_DIR}")
    print(f"manifest: {MANIFEST}")
    return len(records)

if __name__ == "__main__":
    main()
