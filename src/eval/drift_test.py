from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

                                                                      
                                                                          
import __main__              

from src.models.baseline import (              
    HybridVectorizer,
    AstStats,
    evaluate,
)

__main__.HybridVectorizer = HybridVectorizer                              
__main__.AstStats = AstStats                              
SPLITS = ROOT / "data" / "splits"
ARTIFACTS = ROOT / "artifacts"
REPORTS = ROOT / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)

def evaluate_block(model, vec, records: list[dict], label_name: str) -> dict:
    if not records:
        return {"name": label_name, "n_total": 0}
    texts = []
    for r in records:
        try:
            texts.append(Path(r["path"]).read_text())
        except UnicodeDecodeError:
            texts.append(Path(r["path"]).read_text(errors="replace"))
    y = np.array([r["label"] for r in records])
    X = vec.transform(texts)
    return evaluate(model, X, y, label_name)

def main() -> None:
    bundle_path = ARTIFACTS / "baseline_clean.pkl"
    with bundle_path.open("rb") as fh:
        bundle = pickle.load(fh)
    vec, model = bundle["vec"], bundle["model"]

    obf_records = []
    with (SPLITS / "obfuscated_eval.jsonl").open() as fh:
        for line in fh:
            obf_records.append(json.loads(line))

    held_out = [r for r in obf_records if r.get("source_split") == "test"]
    held_train = [r for r in obf_records if r.get("source_split") == "train"]

    print(f"obfuscated total = {len(obf_records)}")
    print(f"  source in train (leakage risk): {len(held_train)}")
    print(f"  source in held-out test:        {len(held_out)}")

    techniques = sorted({r["obfuscation"] for r in held_out})
    metrics = {"overall": evaluate_block(model, vec, held_out, "obfuscated_held_out (all)")}
    for tech in techniques:
        sub = [r for r in held_out if r["obfuscation"] == tech]
        metrics[tech] = evaluate_block(model, vec, sub, f"obfuscated::{tech}")

                                                                       
                          
    per_class = {}
    for tech in techniques:
        sub_b = [r for r in held_out if r["obfuscation"] == tech and r["label"] == 0]
        sub_m = [r for r in held_out if r["obfuscation"] == tech and r["label"] == 1]
        per_class[tech] = {
            "benign_obfuscated": evaluate_block(model, vec, sub_b, f"{tech}::benign"),
            "malicious_obfuscated": evaluate_block(model, vec, sub_m, f"{tech}::malicious"),
        }
    metrics["per_class"] = per_class

    out = ARTIFACTS / "baseline_drift_metrics.json"
    with out.open("w") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"\nsaved drift metrics -> {out}")

    _write_report(metrics, techniques)

def _write_report(metrics: dict, techniques: list[str]) -> None:
    lines = [
        "# Stage 4 — Baseline drift on obfuscation",
        "",
        "Baseline classifier was trained on **clean** scripts only. Below is",
        "its performance on held-out scripts that were obfuscated with each",
        "technique. Only sources whose `source_id` did NOT appear in training",
        "are included — eliminates structural leakage.",
        "",
        "## Aggregate per technique",
        "",
        "| Technique | Acc | Precision | Recall | F1 | ROC-AUC | n |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    overall = metrics["overall"]
    lines.append(
        f"| **all** | {overall['accuracy']:.3f} | {overall['precision']:.3f} | "
        f"{overall['recall']:.3f} | {overall['f1']:.3f} | {overall['roc_auc']:.3f} | {overall['n_total']} |"
    )
    for tech in techniques:
        m = metrics[tech]
        lines.append(
            f"| {tech} | {m['accuracy']:.3f} | {m['precision']:.3f} | "
            f"{m['recall']:.3f} | {m['f1']:.3f} | {m['roc_auc']:.3f} | {m['n_total']} |"
        )

    lines += [
        "",
        "## Per-class survival",
        "",
        "How often does each class get classified correctly when obfuscated?",
        "",
        "| Technique | Benign correctly classified | Malicious detected |",
        "|---|---:|---:|",
    ]
    for tech in techniques:
        pc = metrics["per_class"][tech]
                                                                            
        b = pc["benign_obfuscated"]
        m = pc["malicious_obfuscated"]
        b_acc = b.get("accuracy", float("nan"))
        m_recall = m.get("recall", float("nan"))
        lines.append(
            f"| {tech} | {b_acc:.3f}  ({b['n_total']}) | {m_recall:.3f}  ({m['n_total']}) |"
        )

    out = REPORTS / "04_baseline_drift.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote report -> {out}")

if __name__ == "__main__":
    main()
