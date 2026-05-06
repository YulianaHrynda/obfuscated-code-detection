from __future__ import annotations

import argparse
import ast as _ast
import json
import pickle
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import __main__

try:
    from src.features import HybridVectorizer, AstStats
    __main__.HybridVectorizer = HybridVectorizer
    __main__.AstStats = AstStats
except ImportError:
    pass

DEFAULT_MODEL  = ROOT / "artifacts" / "augmented_model.pkl"
FALLBACK_MODEL = ROOT / "artifacts" / "baseline_clean.pkl"

STRATEGIES = ("strict", "majority", "mean")


@dataclass
class FileScore:
    relpath: str
    score: float
    n_bytes: int
    parses: bool


@dataclass
class ScanReport:
    source: str
    n_files: int
    files: list[FileScore]
    suspicious_thr: float
    malicious_thr: float
    strategy: str = "mean"

    @property
    def max_score(self) -> float:
        return max((f.score for f in self.files), default=0.0)

    @property
    def mean_score(self) -> float:
        return sum(f.score for f in self.files) / len(self.files) if self.files else 0.0

    @property
    def n_high_risk(self) -> int:
        return sum(1 for f in self.files if f.score >= self.malicious_thr)

    @property
    def n_suspicious(self) -> int:
        return sum(1 for f in self.files if self.suspicious_thr <= f.score < self.malicious_thr)

    @property
    def aggregate_score(self) -> float:
        if not self.files:
            return 0.0
        values = [f.score for f in self.files]
        if self.strategy == "mean":
            return sum(values) / len(values)
        if self.strategy == "majority":
            return sum(1 for v in values if v >= self.suspicious_thr) / len(values)
        return max(values)

    @property
    def verdict(self) -> str:
        if not self.files:
            return "SAFE"
        if self.strategy == "strict":
            if self.n_high_risk > 0:
                return "BLOCK"
            if self.n_suspicious > 0:
                return "SUSPICIOUS"
            return "SAFE"
        if self.strategy == "majority":
            ratio = self.aggregate_score
            if ratio >= 0.30:
                return "BLOCK"
            if ratio >= 0.10:
                return "SUSPICIOUS"
            return "SAFE"
        agg = self.aggregate_score
        if agg >= self.malicious_thr:
            return "BLOCK"
        if agg >= self.suspicious_thr:
            return "SUSPICIOUS"
        return "SAFE"

    @property
    def exit_code(self) -> int:
        return {"SAFE": 0, "SUSPICIOUS": 1, "BLOCK": 2}[self.verdict]


def fetch_from_pypi(spec: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "download", "--no-deps",
         "--no-build-isolation", "-d", str(dest), spec],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pip download failed:\n{result.stderr}")
    archives = sorted(dest.glob("*"))
    if not archives:
        raise RuntimeError(f"no archive downloaded for {spec}")
    return archives[0]


def extract_archive(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive) as tf:
            tf.extractall(dest)
    else:
        raise RuntimeError(f"unsupported archive: {archive.name}")
    return dest


def collect_py_files(root: Path) -> list[Path]:
    if root.is_file() and root.suffix == ".py":
        return [root]
    return sorted(p for p in root.rglob("*.py") if p.is_file())


def read_text_safe(path: Path, max_bytes: int = 1_000_000) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="latin-1")
        except UnicodeDecodeError:
            return None
    except OSError:
        return None


def load_model(path: Path):
    with path.open("rb") as fh:
        bundle = pickle.load(fh)
    return bundle["vec"], bundle["model"]


def score_files(vec, model, py_files: list[Path], package_root: Path) -> list[FileScore]:
    if not py_files:
        return []
    texts, keep = [], []
    for path in py_files:
        text = read_text_safe(path)
        if text is not None:
            texts.append(text)
            keep.append(path)
    if not texts:
        return []
    X = vec.transform(texts)
    proba = model.predict_proba(X)[:, 1]
    result = []
    for path, p, text in zip(keep, proba, texts):
        try:
            relpath = str(path.relative_to(package_root))
        except ValueError:
            relpath = path.name
        try:
            _ast.parse(text)
            parses = True
        except SyntaxError:
            parses = False
        result.append(FileScore(relpath=relpath, score=float(p),
                                n_bytes=len(text.encode("utf-8")), parses=parses))
    return result


def render_human(report: ScanReport) -> str:
    lines = [
        f"Source   : {report.source}",
        f"Strategy : {report.strategy}",
        f"Files    : {report.n_files}",
    ]
    if not report.files:
        lines.append("VERDICT  : SAFE (no Python source)")
        return "\n".join(lines)

    lines += ["", "Top files by score:"]
    lines.append(f"  {'score':>6}  path")
    for f in sorted(report.files, key=lambda x: x.score, reverse=True)[:10]:
        if f.score >= report.malicious_thr:
            tag = "  <- MALICIOUS"
        elif f.score >= report.suspicious_thr:
            tag = "  <- suspicious"
        else:
            tag = ""
        lines.append(f"  {f.score:6.3f}  {f.relpath}{tag}")

    lines += [
        "",
        f"  mean score      : {report.mean_score:.3f}",
        f"  aggregate score : {report.aggregate_score:.3f}  ({report.strategy})",
        f"  malicious files : {report.n_high_risk}  (>= {report.malicious_thr})",
        f"  suspicious files: {report.n_suspicious}  ({report.suspicious_thr} – {report.malicious_thr})",
        "",
        f"VERDICT  : {report.verdict}",
    ]
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return json.dumps({
        "source": report.source,
        "strategy": report.strategy,
        "verdict": report.verdict,
        "n_files": report.n_files,
        "mean_score": round(report.mean_score, 4),
        "aggregate_score": round(report.aggregate_score, 4),
        "malicious_count": report.n_high_risk,
        "suspicious_count": report.n_suspicious,
        "suspicious_threshold": report.suspicious_thr,
        "malicious_threshold": report.malicious_thr,
        "files": [
            {"path": f.relpath, "score": f.score, "bytes": f.n_bytes, "parses": f.parses}
            for f in sorted(report.files, key=lambda x: x.score, reverse=True)
        ],
    }, indent=2)


def resolve_source(args, workdir: Path) -> tuple[Path, str]:
    if args.name:
        archive_dir = workdir / "download"
        archive = fetch_from_pypi(args.name, archive_dir)
        extract_dir = workdir / "extracted"
        extract_archive(archive, extract_dir)
        return extract_dir, f"pypi:{args.name}"
    src = Path(args.file).resolve()
    if not src.exists():
        raise RuntimeError(f"path not found: {src}")
    if src.is_file() and src.suffix == ".py":
        return src, str(src)
    if src.is_file():
        extract_dir = workdir / "extracted"
        extract_archive(src, extract_dir)
        return extract_dir, str(src)
    return src, str(src)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a Python package for malicious code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "strategies:\n"
            "  strict   — any file >= malicious-threshold → BLOCK  (most sensitive)\n"
            "  majority — >= 30%% of files above suspicious-threshold → BLOCK\n"
            "  mean     — mean score >= thresholds → verdict  (recommended, fewest false positives)\n"
        ),
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--name", metavar="PKG", help="PyPI spec, e.g. requests or pkg==1.2.3")
    src.add_argument("--file", metavar="PATH", help=".whl / .tar.gz / .zip / directory / .py file")
    parser.add_argument("--model", default=str(DEFAULT_MODEL))
    parser.add_argument("--strategy", choices=STRATEGIES, default="mean",
                        help="aggregation strategy (default: mean)")
    parser.add_argument("--suspicious-threshold", type=float, default=0.5)
    parser.add_argument("--malicious-threshold", type=float, default=0.8)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    model_path = Path(args.model)
    if not model_path.exists():
        if model_path == DEFAULT_MODEL and FALLBACK_MODEL.exists():
            print(f"warn: augmented model missing, using {FALLBACK_MODEL.name}", file=sys.stderr)
            model_path = FALLBACK_MODEL
        else:
            print(f"error: model not found at {model_path}", file=sys.stderr)
            return 3

    vec, model = load_model(model_path)
    workdir = Path(tempfile.mkdtemp(prefix="pkgscan-"))
    try:
        root, label = resolve_source(args, workdir)
        py_files = collect_py_files(root)
        scores = score_files(vec, model, py_files,
                             package_root=root if root.is_dir() else root.parent)
        report = ScanReport(
            source=label, n_files=len(scores), files=scores,
            suspicious_thr=args.suspicious_threshold,
            malicious_thr=args.malicious_threshold,
            strategy=args.strategy,
        )
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print(render_json(report) if args.json else render_human(report))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
