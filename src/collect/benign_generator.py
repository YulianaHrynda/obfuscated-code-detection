from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Callable

random.seed(42)

                               

def _rand_name(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))

def _rand_filename(ext: str) -> str:
    return f"{_rand_name(random.randint(4, 10))}.{ext}"

def _rand_url() -> str:
    domain = random.choice([
        "api.example.com", "data.public-corp.io", "service.local",
        "backend.company.net", "metrics.internal.com",
    ])
    path = "/".join(_rand_name(random.randint(3, 6)) for _ in range(random.randint(1, 3)))
    return f"https://{domain}/{path}"

def _rand_columns(n: int) -> list[str]:
    return [_rand_name(random.randint(3, 8)) for _ in range(n)]

                                 

def t_csv_read() -> str:
    fname = _rand_filename("csv")
    cols = _rand_columns(random.randint(3, 6))
    target_col = random.choice(cols)
    return f'''"""Read a CSV file and aggregate one column."""
import csv
from collections import Counter

def main():
    counts = Counter()
    with open("{fname}", "r", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            counts[row["{target_col}"]] += 1
    for key, value in counts.most_common(10):
        print(f"{{key}}: {{value}}")

if __name__ == "__main__":
    main()
'''

def t_csv_write() -> str:
    fname = _rand_filename("csv")
    cols = _rand_columns(random.randint(3, 5))
    return f'''"""Write a CSV file from a list of records."""
import csv

records = [
    {{ {", ".join(f'"{c}": {i}' for i, c in enumerate(cols))} }},
    {{ {", ".join(f'"{c}": {i + 10}' for i, c in enumerate(cols))} }},
]

with open("{fname}", "w", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames={cols!r})
    writer.writeheader()
    writer.writerows(records)
'''

def t_json_parse() -> str:
    fname = _rand_filename("json")
    key = _rand_name(6)
    return f'''"""Parse JSON file and filter records by key."""
import json

def filter_by_status(path, status):
    with open(path) as fh:
        data = json.load(fh)
    return [item for item in data if item.get("{key}") == status]

if __name__ == "__main__":
    matches = filter_by_status("{fname}", "active")
    print(f"Found {{len(matches)}} active records")
'''

def t_http_get() -> str:
    url = _rand_url()
    return f'''"""Fetch JSON from an HTTP API."""
import json
import urllib.request

def fetch(url):
    req = urllib.request.Request(url, headers={{"Accept": "application/json"}})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))

if __name__ == "__main__":
    data = fetch("{url}")
    print(json.dumps(data, indent=2)[:500])
'''

def t_http_requests() -> str:
    url = _rand_url()
    return f'''"""Fetch a URL with the requests library."""
import requests

def get_data(endpoint):
    response = requests.get(endpoint, timeout=15)
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    payload = get_data("{url}")
    print(f"Received {{len(payload)}} items")
'''

def t_file_walk() -> str:
    ext = random.choice(["txt", "log", "md", "py", "csv"])
    return f'''"""Walk a directory and report files by size."""
import os
from pathlib import Path

def scan(root):
    sizes = {{}}
    for path in Path(root).rglob("*.{ext}"):
        if path.is_file():
            sizes[str(path)] = path.stat().st_size
    return sorted(sizes.items(), key=lambda kv: kv[1], reverse=True)

if __name__ == "__main__":
    for path, size in scan(".")[:20]:
        print(f"{{size:>10}}  {{path}}")
'''

def t_logging_setup() -> str:
    fname = _rand_filename("log")
    return f'''"""Configure rotating logger and emit a few messages."""
import logging
from logging.handlers import RotatingFileHandler

def setup(name):
    handler = RotatingFileHandler("{fname}", maxBytes=1024 * 1024, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

if __name__ == "__main__":
    log = setup("app")
    log.info("startup complete")
    log.warning("config flag missing, using default")
'''

def t_file_copy() -> str:
    src = _rand_filename(random.choice(["txt", "csv", "json"]))
    dst = _rand_filename(random.choice(["txt", "csv", "json"]))
    return f'''"""Copy a file with shutil."""
import shutil
from pathlib import Path

src = Path("{src}")
dst = Path("backup") / "{dst}"
dst.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(src, dst)
print(f"Copied {{src}} -> {{dst}}")
'''

def t_archive() -> str:
    name = _rand_name()
    return f'''"""Create a zip archive of a directory."""
import zipfile
from pathlib import Path

def make_archive(src_dir, archive_path):
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in Path(src_dir).rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(src_dir))

if __name__ == "__main__":
    make_archive("./data", "{name}.zip")
'''

def t_data_filter() -> str:
    col = _rand_name(5)
    threshold = random.randint(10, 1000)
    return f'''"""Filter rows from a list of dicts by threshold."""
def filter_records(records, key, threshold):
    return [r for r in records if r.get(key, 0) >= threshold]

if __name__ == "__main__":
    sample = [
        {{"id": i, "{col}": i * 7}} for i in range(100)
    ]
    keep = filter_records(sample, "{col}", {threshold})
    print(f"kept {{len(keep)}} of {{len(sample)}}")
'''

def t_class_dataclass() -> str:
    fields = _rand_columns(random.randint(2, 4))
    field_lines = "\n".join(f"    {f}: str" for f in fields)
    ctor_args = ", ".join(f'{f}=f"value-{{i}}"' for f in fields)
    return f'''"""Define a dataclass and serialize to JSON."""
import json
from dataclasses import dataclass, asdict

@dataclass
class Item:
{field_lines}

def serialize(items):
    return json.dumps([asdict(i) for i in items], indent=2)

if __name__ == "__main__":
    items = [Item({ctor_args}) for i in range(5)]
    print(serialize(items))
'''

def t_argparse_cli() -> str:
    arg = _rand_name(6)
    return f'''"""Simple CLI with argparse."""
import argparse

def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--{arg}", required=True, help="path to input")
    parser.add_argument("--limit", type=int, default=10)
    return parser

def main():
    args = build_parser().parse_args()
    print(f"processing {{args.{arg}}} with limit={{args.limit}}")

if __name__ == "__main__":
    main()
'''

def t_pandas_transform() -> str:
    cols = _rand_columns(3)
    return f'''"""Read CSV with pandas and compute groupby stats."""
import pandas as pd

def summarize(path):
    df = pd.read_csv(path)
    grouped = df.groupby("{cols[0]}")["{cols[1]}"].agg(["mean", "std", "count"])
    return grouped.reset_index()

if __name__ == "__main__":
    result = summarize("{_rand_filename("csv")}")
    print(result.head())
'''

def t_regex_extract() -> str:
    pattern = random.choice([
        r"\\b\\d{3}-\\d{4}\\b",
        r"[A-Z]{2,}\\d+",
        r"\\w+@\\w+\\.\\w+",
    ])
    return f'''"""Extract patterns from a text file with regex."""
import re

def extract(path, pattern):
    matches = []
    with open(path) as fh:
        for line in fh:
            matches.extend(re.findall(pattern, line))
    return matches

if __name__ == "__main__":
    found = extract("{_rand_filename('txt')}", r"{pattern}")
    print(f"found {{len(found)}} matches")
'''

def t_datetime_report() -> str:
    return f'''"""Generate a daily report timestamped with current date."""
from datetime import datetime, timedelta

def build_report(days=7):
    today = datetime.now()
    rows = []
    for i in range(days):
        day = today - timedelta(days=i)
        rows.append({{"date": day.strftime("%Y-%m-%d"), "events": (i + 1) * 13}})
    return rows

if __name__ == "__main__":
    for row in build_report():
        print(row)
'''

def t_yaml_config() -> str:
    fname = _rand_filename("yaml")
    return f'''"""Load YAML config and validate required keys."""
import yaml

REQUIRED = ["host", "port", "name"]

def load_config(path):
    with open(path) as fh:
        cfg = yaml.safe_load(fh)
    missing = [k for k in REQUIRED if k not in cfg]
    if missing:
        raise ValueError(f"missing keys: {{missing}}")
    return cfg

if __name__ == "__main__":
    config = load_config("{fname}")
    print(config)
'''

def t_sqlite_query() -> str:
    table = _rand_name(6)
    col = _rand_name(5)
    return f'''"""Read from a sqlite database."""
import sqlite3

def fetch_top(db_path, limit=10):
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT * FROM {table} ORDER BY {col} DESC LIMIT ?", (limit,))
        return cur.fetchall()
    finally:
        conn.close()

if __name__ == "__main__":
    rows = fetch_top("app.db")
    for row in rows:
        print(row)
'''

def t_email_validation() -> str:
    return '''"""Simple email validation utility."""
import re

EMAIL_RE = re.compile(r"^[\\w.+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$")

def is_valid(email):
    return bool(EMAIL_RE.match(email or ""))

if __name__ == "__main__":
    samples = ["user@example.com", "broken@", "ok.name+tag@domain.co"]
    for s in samples:
        print(f"{s}: {is_valid(s)}")
'''

def t_hash_file() -> str:
    return f'''"""Compute SHA256 hash of a file."""
import hashlib
from pathlib import Path

def sha256(path, chunk_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()

if __name__ == "__main__":
    print(sha256("{_rand_filename('bin')}"))
'''

def t_threadpool_map() -> str:
    return f'''"""Run a CPU-light task across a thread pool."""
from concurrent.futures import ThreadPoolExecutor

def fetch_meta(item_id):
    return {{"id": item_id, "score": item_id * 3 % 17}}

if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(fetch_meta, range(20)))
    print(f"got {{len(results)}} records")
'''

TEMPLATES: list[Callable[[], str]] = [
    t_csv_read, t_csv_write, t_json_parse, t_http_get, t_http_requests,
    t_file_walk, t_logging_setup, t_file_copy, t_archive, t_data_filter,
    t_class_dataclass, t_argparse_cli, t_pandas_transform, t_regex_extract,
    t_datetime_report, t_yaml_config, t_sqlite_query, t_email_validation,
    t_hash_file, t_threadpool_map,
]

def generate(out_dir: Path, n: int = 1500) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for i in range(n):
        template = random.choice(TEMPLATES)
        code = template()
        rec_id = f"benign_{i:05d}"
        path = out_dir / f"{rec_id}.py"
        path.write_text(code)
        records.append({
            "id": rec_id,
            "path": str(path),
            "label": 0,
            "label_name": "benign",
            "template": template.__name__,
            "obfuscation": None,
        })
    return records

if __name__ == "__main__":
    out = Path(__file__).resolve().parents[2] / "data" / "raw" / "benign"
    n = 1500
    records = generate(out, n=n)
    manifest = out.parent.parent / "splits" / "benign_manifest.jsonl"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} benign scripts to {out}")
    print(f"manifest at {manifest}")
