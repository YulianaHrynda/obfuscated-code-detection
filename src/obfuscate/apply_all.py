from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.obfuscate.techniques import TECHNIQUES, apply              

def process_manifest(manifest_path: Path, out_root: Path, manifest_out: Path) -> int:
    written = 0
    with manifest_out.open("a") as out_fh:
        with manifest_path.open() as fh:
            for line in fh:
                rec = json.loads(line)
                src_path = Path(rec["path"])
                src = src_path.read_text()
                for tech in TECHNIQUES:
                    try:
                        obf = apply(src, tech, seed=hash(rec["id"]) & 0xFFFFFFFF)
                    except Exception as e:        
                                                                                                  
                                                      
                        print(f"  skip {rec['id']} / {tech}: {type(e).__name__}: {e}")
                        continue
                    out_dir = out_root / tech
                    out_dir.mkdir(parents=True, exist_ok=True)
                    out_path = out_dir / f"{rec['id']}.py"
                    out_path.write_text(obf)
                    new_rec = {
                        "id": f"{rec['id']}__{tech}",
                        "source_id": rec["id"],
                        "path": str(out_path),
                        "label": rec["label"],
                        "label_name": rec["label_name"],
                        "template": rec.get("template"),
                        "obfuscation": tech,
                    }
                    out_fh.write(json.dumps(new_rec) + "\n")
                    written += 1
    return written

def main() -> None:
    out_root = ROOT / "data" / "obfuscated"
    manifest_out = ROOT / "data" / "splits" / "obfuscated_manifest.jsonl"
    manifest_out.unlink(missing_ok=True)
    out_root.mkdir(parents=True, exist_ok=True)

    total = 0
    for name in [
        "benign_manifest.jsonl",
        "benign_ambiguous_manifest.jsonl",
        "benign_real_manifest.jsonl",
        "malicious_manifest.jsonl",
        "malicious_real_manifest.jsonl",
    ]:
        manifest_path = ROOT / "data" / "splits" / name
        if not manifest_path.exists():
            print(f"{name}: skipped (not found)")
            continue
        n = process_manifest(manifest_path, out_root, manifest_out)
        print(f"{name}: {n} obfuscated artifacts")
        total += n
    print(f"total: {total}")
    print(f"manifest: {manifest_out}")

if __name__ == "__main__":
    main()
