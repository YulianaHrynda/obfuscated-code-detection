from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPLITS = ROOT / "data" / "splits"

random.seed(0)

def load_manifest(path: Path) -> list[dict]:
    with path.open() as fh:
        return [json.loads(line) for line in fh]

def write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

def stratified_split(records: list[dict], ratios=(0.8, 0.1, 0.1), seed: int = 0):
    rng = random.Random(seed)
    by_label: dict[int, list[dict]] = {}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)
    train, val, test = [], [], []
    for items in by_label.values():
        rng.shuffle(items)
        n = len(items)
        n_train = int(n * ratios[0])
        n_val = int(n * ratios[1])
        train.extend(items[:n_train])
        val.extend(items[n_train:n_train + n_val])
        test.extend(items[n_train + n_val:])
    rng.shuffle(train); rng.shuffle(val); rng.shuffle(test)
    return train, val, test

def main() -> None:
    benign_synth = load_manifest(SPLITS / "benign_manifest.jsonl")
    benign_amb  = load_manifest(SPLITS / "benign_ambiguous_manifest.jsonl") if (SPLITS / "benign_ambiguous_manifest.jsonl").exists() else []
    benign_real = load_manifest(SPLITS / "benign_real_manifest.jsonl")      if (SPLITS / "benign_real_manifest.jsonl").exists()      else []
    benign_pypi = load_manifest(SPLITS / "benign_pypi_manifest.jsonl")      if (SPLITS / "benign_pypi_manifest.jsonl").exists()      else []
    mal_synth   = load_manifest(SPLITS / "malicious_manifest.jsonl")
    mal_real    = load_manifest(SPLITS / "malicious_real_manifest.jsonl")   if (SPLITS / "malicious_real_manifest.jsonl").exists()   else []

    for r in benign_synth:
        r.setdefault("source", "synthetic")
    for r in mal_synth:
        r.setdefault("source", "synthetic")

    clean = benign_synth + benign_amb + benign_real + benign_pypi + mal_synth + mal_real
    train, val, test = stratified_split(clean)
    write_jsonl(SPLITS / "clean_train.jsonl", train)
    write_jsonl(SPLITS / "clean_val.jsonl", val)
    write_jsonl(SPLITS / "clean_test.jsonl", test)

                                                                       
                                                                         
    test_real_mal = [r for r in test if r["label"] == 1 and r.get("source") == "datadog"]
    test_synth_mal = [r for r in test if r["label"] == 1 and r.get("source") != "datadog"]
    test_benign_easy = [r for r in test if r["label"] == 0 and r.get("source") != "ambiguous_benign"]
    test_benign_amb = [r for r in test if r["label"] == 0 and r.get("source") == "ambiguous_benign"]

    write_jsonl(SPLITS / "real_eval.jsonl", test_real_mal + test_benign_easy + test_benign_amb)
    write_jsonl(SPLITS / "synth_eval.jsonl", test_synth_mal + test_benign_easy + test_benign_amb)
                                                                           
    write_jsonl(SPLITS / "hard_eval.jsonl", test_real_mal + test_benign_amb)

                                                                            
    obf = load_manifest(SPLITS / "obfuscated_manifest.jsonl")
    train_ids = {r["id"] for r in train}
    val_ids = {r["id"] for r in val}
    for r in obf:
        if r["source_id"] in train_ids:
            r["source_split"] = "train"
        elif r["source_id"] in val_ids:
            r["source_split"] = "val"
        else:
            r["source_split"] = "test"
    write_jsonl(SPLITS / "obfuscated_eval.jsonl", obf)

    print(f"clean_train: {len(train)}  (benign={sum(1 for r in train if r['label']==0)}, mal={sum(1 for r in train if r['label']==1)})")
    print(f"clean_val:   {len(val)}")
    print(f"clean_test:  {len(test)}  (benign_easy={len(test_benign_easy)}, benign_amb={len(test_benign_amb)}, real_mal={len(test_real_mal)}, synth_mal={len(test_synth_mal)})")
    print(f"real_eval:   {len(test_real_mal) + len(test_benign_easy) + len(test_benign_amb)}  (benign={len(test_benign_easy) + len(test_benign_amb)}, real_mal={len(test_real_mal)})")
    print(f"synth_eval:  {len(test_synth_mal) + len(test_benign_easy) + len(test_benign_amb)}  (benign={len(test_benign_easy) + len(test_benign_amb)}, synth_mal={len(test_synth_mal)})")
    print(f"hard_eval:   {len(test_real_mal) + len(test_benign_amb)}  (benign_amb={len(test_benign_amb)}, real_mal={len(test_real_mal)})")
    print(f"obfuscated_eval: {len(obf)} total")
    by_src = {}
    for r in obf:
        by_src[r["source_split"]] = by_src.get(r["source_split"], 0) + 1
    print(f"  by source split: {by_src}")

if __name__ == "__main__":
    main()
