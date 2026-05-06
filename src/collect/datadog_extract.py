from __future__ import annotations

import json
import random
import zipfile
from pathlib import Path

DATASET_ROOT = Path("/tmp/datadog-malware/samples/pypi/malicious_intent")
OUT_DIR = Path(__file__).resolve().parents[2] / "data" / "raw" / "malicious_real"
MANIFEST = Path(__file__).resolve().parents[2] / "data" / "splits" / "malicious_real_manifest.jsonl"
PASSWORD = b"infected"
TARGET_FILES = ("__init__.py", "setup.py")
MAX_SAMPLES = 800
MAX_BYTES = 200_000                                                           

def main() -> int:
    if not DATASET_ROOT.exists():
        print(f"DataDog dataset not found at {DATASET_ROOT}; skipping real-malware extraction.")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(0)
    zips = sorted(DATASET_ROOT.rglob("*.zip"))
    rng.shuffle(zips)

    written = 0
    records = []
    for zip_path in zips:
        if written >= MAX_SAMPLES:
            break
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.setpassword(PASSWORD)
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > MAX_BYTES:
                        continue
                    name = info.filename.rsplit("/", 1)[-1]
                    if name not in TARGET_FILES:
                        continue
                    try:
                        raw = zf.read(info)
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
                    try:
                        text = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        try:
                            text = raw.decode("latin-1")
                        except UnicodeDecodeError:
                            continue
                    if not text.strip():
                        continue
                    rec_id = f"malreal_{written:05d}"
                    out_path = OUT_DIR / f"{rec_id}.py"
                    out_path.write_text(text)
                    records.append({
                        "id": rec_id,
                        "path": str(out_path),
                        "label": 1,
                        "label_name": "malicious",
                        "template": f"datadog::{zip_path.parent.name}/{name}",
                        "obfuscation": None,
                        "source": "datadog",
                    })
                    written += 1
                    if written >= MAX_SAMPLES:
                        break
        except (zipfile.BadZipFile, OSError) as e:
            print(f"  skip {zip_path.name}: {e}")
            continue

    with MANIFEST.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    print(f"extracted {written} real malicious .py files from {len(zips)} zips")
    print(f"manifest: {MANIFEST}")
    return written

if __name__ == "__main__":
    main()
