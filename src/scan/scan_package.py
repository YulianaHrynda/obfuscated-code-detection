from __future__ import annotations

import argparse
import json
import pickle
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import __main__  # noqa: E402

from src.features import HybridVectorizer, AstStats  # noqa: E402

__main__.HybridVectorizer = HybridVectorizer  # type: ignore[attr-defined]
__main__.AstStats = AstStats  # type: ignore[attr-defined]


DEFAULT_MODEL = ROOT / "artifacts" / "augmented_model.pkl"
FALLBACK_MODEL = ROOT / "artifacts" / "baseline_clean.pkl"


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

    @property
    def max_score(self) -> float:
        return max((f.score for f in self.files), default=0.0)

    @property
    def mean_score(self) -> float:
        if not self.files:
            return 0.0
        return sum(f.score for f in self.files) / len(self.files)

    @property
    def n_high_risk(self) -> int:
        return sum(1 for f in self.files if f.score >= self.malicious_thr)

    @property
    def n_suspicious(self) -> int:
        return sum(1 for f in self.files
                   if self.suspicious_thr <= f.score < self.malicious_thr)

    @property
    def verdict(self) -> str:
        if self.n_high_risk > 0:
            return "BLOCK"
        if self.n_suspicious > 0:
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
        size = path.stat().st_size
    except OSError:
        return None
    if size > max_bytes:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="latin-1")
        except UnicodeDecodeError:
            return None


def load_model(path: Path):
    with path.open("rb") as fh:
        bundle = pickle.load(fh)
    return bundle["vec"], bundle["model"]


def score_files(vec, model, py_files: list[Path], package_root: Path) -> list[FileScore]:
    if not py_files:
        return []
    texts: list[str] = []
    keep: list[Path] = []
    for path in py_files:
        text = read_text_safe(path)
        if text is None:
            continue
        texts.append(text)
        keep.append(path)
    if not texts:
        return []
    X = vec.transform(texts)
    proba = model.predict_proba(X)[:, 1]
    scores = []
    import ast as _ast
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
        scores.append(FileScore(
            relpath=relpath, score=float(p),
            n_bytes=len(text.encode("utf-8")), parses=parses,
        ))
    return scores


def render_human(report: ScanReport) -> str:
    lines = []
    lines.append(f"Scanning: {report.source}")
    lines.append(f"Found .py files: {report.n_files}")
    if report.n_files == 0:
        lines.append("VERDICT: SAFE (no Python source to scan)")
        return "\n".join(lines)

    sorted_files = sorted(report.files, key=lambda f: f.score, reverse=True)
    show = sorted_files[:10]
    lines.append("")
    lines.append("Top files by malicious score:")
    lines.append(f"  {'score':>6}  {'path':<60}  parses")
    for f in show:
        flag = ""
        if f.score >= report.malicious_thr:
            flag = "  <- MALICIOUS"
        elif f.score >= report.suspicious_thr:
            flag = "  <- suspicious"
        lines.append(f"  {f.score:6.3f}  {f.relpath:<60}  {'yes' if f.parses else 'no '}{flag}")

    lines.append("")
    lines.append("Summary:")
    lines.append(f"  files scanned   : {report.n_files}")
    lines.append(f"  mean score      : {report.mean_score:.3f}")
    lines.append(f"  max score       : {report.max_score:.3f}")
    lines.append(f"  malicious files : {report.n_high_risk} (>= {report.malicious_thr})")
    lines.append(f"  suspicious files: {report.n_suspicious} ({report.suspicious_thr} - {report.malicious_thr})")
    lines.append("")
    lines.append(f"VERDICT: {report.verdict}")
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return json.dumps({
        "source": report.source,
        "n_files": report.n_files,
        "verdict": report.verdict,
        "max_score": report.max_score,
        "mean_score": report.mean_score,
        "malicious_count": report.n_high_risk,
        "suspicious_count": report.n_suspicious,
        "suspicious_threshold": report.suspicious_thr,
        "malicious_threshold": report.malicious_thr,
        "files": [
            {"path": f.relpath, "score": f.score, "bytes": f.n_bytes, "parses": f.parses}
            for f in sorted(report.files, key=lambda x: x.score, reverse=True)
        ],
    }, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a Python package for malicious code before installing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument("--name", help="PyPI package spec, e.g. requests or pkg==1.2.3")
    src_group.add_argument("--file", help="Path to .whl, .tar.gz, .zip, .py, or a directory")
    parser.add_argument("--model", default=str(DEFAULT_MODEL))
    parser.add_argument("--suspicious-threshold", type=float, default=0.5)
    parser.add_argument("--malicious-threshold", type=float, default=0.8)
    parser.add_argument("--json", action="store_true")
    return parser


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
    if src.is_file():
        if src.suffix == ".py":
            return src, str(src)
        extract_dir = workdir / "extracted"
        extract_archive(src, extract_dir)
        return extract_dir, str(src)
    return src, str(src)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    model_path = Path(args.model)
    if not model_path.exists():
        if FALLBACK_MODEL.exists() and model_path == DEFAULT_MODEL:
            print(f"warn: {model_path} missing, falling back to {FALLBACK_MODEL.name}",
                  file=sys.stderr)
            model_path = FALLBACK_MODEL
        else:
            print(
                f"error: model not found at {model_path}\n"
                "Run notebooks/baseline_simple.ipynb (or src/models training scripts) "
                "to produce artifacts/augmented_model.pkl first.",
                file=sys.stderr,
            )
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
        )
    except Exception as e:  # noqa: BLE001
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if args.json:
        print(render_json(report))
    else:
        print(render_human(report))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
