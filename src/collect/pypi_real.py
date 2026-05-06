from __future__ import annotations

import ast
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

MAX_FILES = 1000
MIN_BYTES = 200
MAX_BYTES = 50_000

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "data" / "raw" / "benign_pypi"
MANIFEST = ROOT / "data" / "splits" / "benign_pypi_manifest.jsonl"

TOP_PACKAGES = [
    "numpy", "requests", "flask", "django", "pandas", "scipy",
    "matplotlib", "pillow", "fastapi", "sqlalchemy", "pydantic",
    "pytest", "click", "boto3", "cryptography", "celery", "redis",
    "httpx", "aiohttp", "uvicorn", "starlette", "typing-extensions",
    "packaging", "setuptools", "wheel", "pip", "six", "attrs",
    "pyyaml", "toml", "tomli", "charset-normalizer", "urllib3",
    "certifi", "idna", "colorama", "rich", "tqdm", "black",
    "mypy", "pylint", "flake8", "isort", "pytest-asyncio",
    "werkzeug", "jinja2", "markupsafe", "itsdangerous", "blinker",
    "psutil", "paramiko", "fabric", "invoke", "docker",
]


def _download_wheel(pkg: str, tmp_dir: Path) -> Path | None:
    result = subprocess.run(
        [sys.executable, "-m", "pip", "download", "--no-deps",
         "--only-binary=:all:", "-d", str(tmp_dir), pkg],
        capture_output=True, text=True,
    )
    wheels = list(tmp_dir.glob("*.whl"))
    return wheels[0] if wheels else None


def _extract_py_files(wheel_path: Path, pkg_name: str) -> list[tuple[str, str]]:
    results = []
    try:
        with zipfile.ZipFile(wheel_path) as zf:
            for name in zf.namelist():
                if not name.endswith(".py"):
                    continue
                basename = Path(name).name
                if basename.startswith("test_") or basename.endswith("_test.py"):
                    continue
                if "test" in name.lower().split("/"):
                    continue
                try:
                    text = zf.read(name).decode("utf-8", errors="replace")
                except Exception:
                    continue
                size = len(text.encode("utf-8"))
                if size < MIN_BYTES or size > MAX_BYTES:
                    continue
                try:
                    ast.parse(text)
                except (SyntaxError, ValueError):
                    continue
                results.append((text, f"pypi::{pkg_name}/{basename}"))
    except zipfile.BadZipFile:
        pass
    return results


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    seen_hashes: set[str] = set()
    records = []

    for pkg in TOP_PACKAGES:
        if len(records) >= MAX_FILES:
            break
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_dir = Path(tmp)
                print(f"  {pkg} — downloading...")
                wheel_path = _download_wheel(pkg, tmp_dir)
                if not wheel_path:
                    print(f"    no wheel found, skipping")
                    continue
                py_files = _extract_py_files(wheel_path, pkg)

            added = 0
            for text, template in py_files:
                if len(records) >= MAX_FILES:
                    break
                h = hashlib.sha1(text.encode("utf-8")).hexdigest()
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                rec_id = f"benign_pypi_{len(records):05d}"
                out_path = OUT_DIR / f"{rec_id}.py"
                out_path.write_text(text, encoding="utf-8")
                records.append({
                    "id": rec_id,
                    "path": str(out_path),
                    "label": 0,
                    "label_name": "benign",
                    "template": template,
                    "obfuscation": None,
                    "source": "pypi_real",
                })
                added += 1
            print(f"    added {added} files (total {len(records)})")

        except Exception as e:
            print(f"  {pkg}: error — {e}")

    with MANIFEST.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    print(f"\nwrote {len(records)} PyPI files → {OUT_DIR}")
    print(f"manifest → {MANIFEST}")


if __name__ == "__main__":
    main()
