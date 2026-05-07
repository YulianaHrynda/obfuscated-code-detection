from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import __main__

from src.features import HybridVectorizer, AstStats
__main__.HybridVectorizer = HybridVectorizer
__main__.AstStats = AstStats

from src.scan.scan_package import (
    DEFAULT_MODEL, FALLBACK_MODEL, FileScore, ScanReport,
    collect_py_files, extract_archive, load_model, score_files,
)


BENIGN_PACKAGES = [
    "requests", "urllib3", "numpy", "pandas", "scipy", "scikit-learn",
    "matplotlib", "pytest", "click", "flask", "django", "fastapi",
    "pydantic", "sqlalchemy", "boto3", "redis", "celery", "jinja2",
    "pyyaml", "rich", "typer", "httpx", "attrs", "loguru",
    "tqdm", "beautifulsoup4", "lxml", "pillow", "cryptography", "packaging",
]
MAL_DIR = ROOT / "data" / "raw" / "malicious_real"

STRATEGIES = ("strict", "majority", "mean")


@dataclass
class CaseResult:
    label: str
    name: str
    n_files: int
    max_score: float
    mean_score: float
    verdict_strict: str
    verdict_majority: str
    verdict_mean: str
    download_seconds: float = 0.0
    error: str = ""


def cached_download(spec: str, cache_dir: Path) -> Path | None:
    pkg_dir = cache_dir / spec
    extract_dir = pkg_dir / "extracted"
    if extract_dir.exists() and any(extract_dir.iterdir()):
        return extract_dir
    pkg_dir.mkdir(parents=True, exist_ok=True)
    download_dir = pkg_dir / "download"
    download_dir.mkdir(exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "download", "--no-deps",
         "--no-build-isolation", "-d", str(download_dir), spec],
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode != 0:
        return None
    archives = sorted(download_dir.glob("*"))
    if not archives:
        return None
    extract_dir.mkdir(exist_ok=True)
    try:
        extract_archive(archives[0], extract_dir)
    except RuntimeError:
        return None
    return extract_dir


def evaluate_directory(vec, model, root: Path,
                       suspicious_thr: float,
                       malicious_thr: float) -> tuple[list[FileScore], dict[str, str]]:
    py_files = collect_py_files(root)
    scores = score_files(vec, model, py_files, root if root.is_dir() else root.parent)
    verdicts = {}
    for strategy in STRATEGIES:
        report = ScanReport(
            source=str(root), n_files=len(scores), files=scores,
            suspicious_thr=suspicious_thr, malicious_thr=malicious_thr,
            strategy=strategy,
        )
        verdicts[strategy] = report.verdict
    return scores, verdicts


def confusion(results: list[CaseResult], strategy: str, label: str) -> tuple[int, int, int]:
    """Return (true_class_count, predicted_block_count, predicted_safe_count) for given true label."""
    sub = [r for r in results if r.label == label]
    field = f"verdict_{strategy}"
    block = sum(1 for r in sub if getattr(r, field) == "BLOCK")
    safe = sum(1 for r in sub if getattr(r, field) == "SAFE")
    susp = len(sub) - block - safe
    return block, susp, safe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-benign", type=int, default=len(BENIGN_PACKAGES))
    parser.add_argument("--n-malicious", type=int, default=100)
    parser.add_argument("--suspicious-threshold", type=float, default=0.5)
    parser.add_argument("--malicious-threshold", type=float, default=0.8)
    parser.add_argument("--cache", default=str(ROOT / ".pkg_cache"))
    parser.add_argument("--out-json", default=str(ROOT / "artifacts" / "scan_benchmark.json"))
    parser.add_argument("--out-csv", default=str(ROOT / "artifacts" / "scan_benchmark.csv"))
    args = parser.parse_args(argv)

    model_path = DEFAULT_MODEL if DEFAULT_MODEL.exists() else FALLBACK_MODEL
    if not model_path.exists():
        print(f"error: no model at {DEFAULT_MODEL} or {FALLBACK_MODEL}", file=sys.stderr)
        return 3
    print(f"loading model: {model_path.name}")
    vec, model = load_model(model_path)

    cache_dir = Path(args.cache)
    cache_dir.mkdir(parents=True, exist_ok=True)
    results: list[CaseResult] = []

    print(f"\n=== benign packages (n={min(args.n_benign, len(BENIGN_PACKAGES))}) ===")
    for spec in BENIGN_PACKAGES[: args.n_benign]:
        t0 = time.time()
        root = cached_download(spec, cache_dir)
        dt = time.time() - t0
        if root is None:
            print(f"  {spec:20s}  download failed")
            results.append(CaseResult(
                label="benign", name=spec, n_files=0,
                max_score=0.0, mean_score=0.0,
                verdict_strict="ERROR", verdict_majority="ERROR", verdict_mean="ERROR",
                download_seconds=dt, error="download failed",
            ))
            continue
        scores, verdicts = evaluate_directory(
            vec, model, root,
            args.suspicious_threshold, args.malicious_threshold,
        )
        max_s = max((s.score for s in scores), default=0.0)
        mean_s = sum(s.score for s in scores) / len(scores) if scores else 0.0
        cr = CaseResult(
            label="benign", name=spec, n_files=len(scores),
            max_score=max_s, mean_score=mean_s,
            verdict_strict=verdicts["strict"],
            verdict_majority=verdicts["majority"],
            verdict_mean=verdicts["mean"],
            download_seconds=dt,
        )
        results.append(cr)
        print(f"  {spec:20s}  files={len(scores):4d}  max={max_s:.3f}  mean={mean_s:.3f}  "
              f"strict={verdicts['strict']:10s}  majority={verdicts['majority']:10s}  mean={verdicts['mean']}")

    print(f"\n=== malicious samples (n={args.n_malicious}) ===")
    if not MAL_DIR.exists():
        print(f"warn: {MAL_DIR} not found, skipping malicious eval")
    else:
        all_mal = sorted(MAL_DIR.glob("*.py"))
        rng = random.Random(0)
        rng.shuffle(all_mal)
        sample = all_mal[: args.n_malicious]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            for path in sample:
                pkg_dir = tmp_root / path.stem
                pkg_dir.mkdir()
                shutil.copy(path, pkg_dir / path.name)
                scores, verdicts = evaluate_directory(
                    vec, model, pkg_dir,
                    args.suspicious_threshold, args.malicious_threshold,
                )
                max_s = max((s.score for s in scores), default=0.0)
                mean_s = sum(s.score for s in scores) / len(scores) if scores else 0.0
                results.append(CaseResult(
                    label="malicious", name=path.stem, n_files=len(scores),
                    max_score=max_s, mean_score=mean_s,
                    verdict_strict=verdicts["strict"],
                    verdict_majority=verdicts["majority"],
                    verdict_mean=verdicts["mean"],
                ))
        mal_results = [r for r in results if r.label == "malicious"]
        for r in mal_results[:10]:
            print(f"  {r.name:20s}  max={r.max_score:.3f}  "
                  f"strict={r.verdict_strict:10s}  majority={r.verdict_majority:10s}  mean={r.verdict_mean}")
        if len(mal_results) > 10:
            print(f"  ... ({len(mal_results) - 10} more)")

    print("\n=== confusion matrix per strategy ===")
    print(f"{'strategy':10s}  {'TN(SAFE)':>10s}  {'FP(BLOCK)':>10s}  {'FN(SAFE)':>10s}  {'TP(BLOCK)':>10s}  "
          f"{'precision':>10s}  {'recall':>10s}  {'F1':>6s}")
    for strategy in STRATEGIES:
        b_block, b_susp, b_safe = confusion(results, strategy, "benign")
        m_block, m_susp, m_safe = confusion(results, strategy, "malicious")
        fp = b_block + b_susp
        tp = m_block + m_susp
        fn = m_safe
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        print(f"{strategy:10s}  {b_safe:>10d}  {fp:>10d}  "
              f"{m_safe:>10d}  {tp:>10d}  "
              f"{precision:>10.3f}  {recall:>10.3f}  {f1:>6.3f}")

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with out_json.open("w") as fh:
        json.dump([asdict(r) for r in results], fh, indent=2)
    print(f"\nwrote {out_json}")

    out_csv = Path(args.out_csv)
    with out_csv.open("w") as fh:
        fh.write("label,name,n_files,max_score,mean_score,strict,majority,mean,error\n")
        for r in results:
            fh.write(f"{r.label},{r.name},{r.n_files},{r.max_score:.4f},{r.mean_score:.4f},"
                     f"{r.verdict_strict},{r.verdict_majority},{r.verdict_mean},{r.error}\n")
    print(f"wrote {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
