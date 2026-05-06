from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Callable

random.seed(2026)

def _name(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))

def _internal_host():
    return random.choice([
        "internal-api.company.svc",
        "monitoring.prod.local",
        "db-primary.cluster.local",
        "vault.internal.com",
        "deploy-orchestrator.svc",
    ])

                                                     

def t_kubectl_deploy() -> str:
    ns = _name(6)
    return f'''"""Apply a Kubernetes manifest with kubectl."""
import subprocess
import sys

def deploy(manifest_path):
    result = subprocess.run(
        ["kubectl", "apply", "-n", "{ns}", "-f", manifest_path],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout

if __name__ == "__main__":
    print(deploy(sys.argv[1]))
'''

def t_docker_build() -> str:
    return '''"""Build and tag a Docker image."""
import subprocess
import argparse

def build(tag, context):
    cmd = ["docker", "build", "-t", tag, context]
    return subprocess.run(cmd, check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--context", default=".")
    args = parser.parse_args()
    build(args.tag, args.context)

if __name__ == "__main__":
    main()
'''

def t_health_check_socket() -> str:
    host = _internal_host()
    port = random.choice([5432, 6379, 9092, 8080, 3306])
    return f'''"""TCP health-check for {host}:{port}."""
import socket
import sys

TIMEOUT = 3.0

def is_alive(host, port, timeout=TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

if __name__ == "__main__":
    ok = is_alive("{host}", {port})
    sys.exit(0 if ok else 1)
'''

def t_slack_notify() -> str:
    return '''"""Post a deployment status to Slack via webhook."""
import os
import json
import requests

WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]

def notify(text, channel="#deploys"):
    payload = {"channel": channel, "text": text, "username": "deploybot"}
    response = requests.post(
        WEBHOOK_URL,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    response.raise_for_status()

if __name__ == "__main__":
    import sys
    notify(sys.argv[1] if len(sys.argv) > 1 else "deploy succeeded")
'''

def t_rsync_backup() -> str:
    return '''"""Run rsync to back up a directory to a remote host."""
import subprocess
import argparse
from pathlib import Path

def backup(src, dst):
    src = Path(src).resolve()
    cmd = ["rsync", "-azP", "--delete", f"{src}/", dst]
    return subprocess.run(cmd, check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("src")
    parser.add_argument("dst", help="user@host:/path")
    args = parser.parse_args()
    backup(args.src, args.dst)

if __name__ == "__main__":
    main()
'''

def t_git_helper() -> str:
    return '''"""Wrapper around `git rev-parse` to fetch the current commit SHA."""
import subprocess

def current_sha(short=False):
    args = ["git", "rev-parse", "--short" if short else "HEAD", "HEAD"]
    if not short:
        args = ["git", "rev-parse", "HEAD"]
    out = subprocess.check_output(args, text=True).strip()
    return out

if __name__ == "__main__":
    print(current_sha(short=True))
'''

def t_prometheus_scrape() -> str:
    host = _internal_host()
    return f'''"""Scrape /metrics from {host} and parse a counter."""
import requests

def scrape(host, port=9090):
    response = requests.get(f"http://{{host}}:{{port}}/metrics", timeout=5)
    response.raise_for_status()
    counters = {{}}
    for line in response.text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        name, _, value = line.partition(" ")
        try:
            counters[name] = float(value)
        except ValueError:
            continue
    return counters

if __name__ == "__main__":
    metrics = scrape("{host}")
    print(f"got {{len(metrics)}} counters")
'''

def t_postgres_psql() -> str:
    return '''"""Run a SQL script against a Postgres database via psql."""
import os
import subprocess
import sys

def run_sql(script_path):
    env = os.environ.copy()
    env.setdefault("PGPASSWORD", os.environ.get("DB_PASSWORD", ""))
    cmd = [
        "psql", "-h", env.get("DB_HOST", "localhost"),
        "-U", env.get("DB_USER", "postgres"),
        "-d", env.get("DB_NAME", "app"),
        "-f", script_path,
    ]
    return subprocess.run(cmd, env=env, check=False)

if __name__ == "__main__":
    sys.exit(run_sql(sys.argv[1]).returncode)
'''

def t_internal_api_post() -> str:
    return '''"""POST a JSON body to an internal service."""
import json
import os
import urllib.request

def post(endpoint, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['SERVICE_TOKEN']}",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())

if __name__ == "__main__":
    result = post(os.environ["API_URL"], {"event": "ping"})
    print(result)
'''

def t_setup_py_legit() -> str:
    name = _name(8)
    return f'''"""Standard setup.py with a custom build step (legit)."""
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
import subprocess

class GenerateProto(build_py):
    """Compile .proto files before packaging."""
    def run(self):
        subprocess.check_call(["protoc", "--python_out=.", "schema.proto"])
        super().run()

setup(
    name="{name}",
    version="1.2.0",
    packages=find_packages(),
    install_requires=["protobuf>=4.0"],
    cmdclass={{"build_py": GenerateProto}},
)
'''

def t_argparse_subcommand() -> str:
    cmd = _name(6)
    return f'''"""CLI tool with subcommands that wrap shell utilities."""
import argparse
import subprocess
import sys

def cmd_status(args):
    return subprocess.run(["systemctl", "status", args.unit], check=False).returncode

def cmd_restart(args):
    return subprocess.run(["systemctl", "restart", args.unit], check=False).returncode

def main():
    parser = argparse.ArgumentParser(prog="{cmd}")
    sub = parser.add_subparsers(dest="action", required=True)
    s = sub.add_parser("status"); s.add_argument("unit"); s.set_defaults(fn=cmd_status)
    r = sub.add_parser("restart"); r.add_argument("unit"); r.set_defaults(fn=cmd_restart)
    args = parser.parse_args()
    sys.exit(args.fn(args))

if __name__ == "__main__":
    main()
'''

def t_eval_safe_expr() -> str:
    return '''"""Safe arithmetic eval using ast.literal_eval (NOT eval())."""
import ast
import operator

OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.USub: operator.neg,
}

def safe_calc(expr):
    node = ast.parse(expr, mode="eval").body
    return _eval_node(node)

def _eval_node(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp):
        return OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp):
        return OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError(f"unsupported: {ast.dump(node)}")

if __name__ == "__main__":
    print(safe_calc("3 * (4 + 2)"))
'''

def t_getattr_dispatch() -> str:
    return '''"""Plugin dispatcher using getattr() — totally legit."""
class Handler:
    def on_create(self, event):
        return f"created: {event['id']}"
    def on_update(self, event):
        return f"updated: {event['id']}"
    def on_delete(self, event):
        return f"deleted: {event['id']}"

def dispatch(handler, event):
    method = getattr(handler, f"on_{event['type']}", None)
    if method is None:
        raise ValueError(f"unknown event type: {event['type']}")
    return method(event)

if __name__ == "__main__":
    h = Handler()
    for evt in [{"type": "create", "id": 1}, {"type": "update", "id": 2}]:
        print(dispatch(h, evt))
'''

def t_base64_encode_legit() -> str:
    return '''"""Encode a binary file as base64 for transport (legit use)."""
import base64
import sys
from pathlib import Path

def encode_file(path):
    data = Path(path).read_bytes()
    return base64.b64encode(data).decode("ascii")

def decode_to_file(blob, path):
    Path(path).write_bytes(base64.b64decode(blob))

if __name__ == "__main__":
    print(encode_file(sys.argv[1])[:120], "...")
'''

def t_signal_handler() -> str:
    return '''"""Trap SIGTERM and shut down gracefully."""
import signal
import sys
import time

shutdown = False

def on_term(signum, frame):
    global shutdown
    shutdown = True

signal.signal(signal.SIGTERM, on_term)

def main():
    while not shutdown:
        time.sleep(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
'''

def t_celery_task() -> str:
    return '''"""Celery task that POSTs results to an internal API."""
import os
import requests
from celery import Celery

app = Celery("worker", broker=os.environ.get("BROKER_URL", "redis://localhost"))

@app.task(name="tasks.report")
def report(job_id, payload):
    response = requests.post(
        os.environ["RESULTS_API"],
        json={"job_id": job_id, "data": payload},
        headers={"Authorization": f"Bearer {os.environ['API_TOKEN']}"},
        timeout=15,
    )
    response.raise_for_status()
    return response.status_code
'''

def t_threadpool_subprocess() -> str:
    return '''"""Run a shell tool across multiple inputs in parallel."""
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def lint_one(path):
    result = subprocess.run(
        ["ruff", "check", path],
        capture_output=True, text=True,
    )
    return path, result.returncode, result.stdout

def lint_all(paths, workers=4):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(lint_one, p) for p in paths]
        return [f.result() for f in as_completed(futures)]

if __name__ == "__main__":
    import sys
    for path, rc, out in lint_all(sys.argv[1:]):
        print(f"{path}: rc={rc}")
'''

def t_systemd_journal() -> str:
    return '''"""Read systemd journal entries via journalctl."""
import json
import subprocess

def recent(unit, n=50):
    out = subprocess.check_output(
        ["journalctl", "-u", unit, "-n", str(n), "-o", "json"],
        text=True,
    )
    entries = []
    for line in out.splitlines():
        if not line.strip():
            continue
        entries.append(json.loads(line))
    return entries

if __name__ == "__main__":
    for entry in recent("nginx"):
        print(entry.get("MESSAGE", "")[:120])
'''

def t_aws_boto_legit() -> str:
    return '''"""List S3 buckets via boto3 with the default credential chain."""
import boto3

def list_buckets():
    client = boto3.client("s3")
    response = client.list_buckets()
    return [b["Name"] for b in response["Buckets"]]

if __name__ == "__main__":
    for name in list_buckets():
        print(name)
'''

def t_health_check_http() -> str:
    host = _internal_host()
    return f'''"""HTTP health probe with retry."""
import time
import requests

URL = "https://{host}/healthz"

def probe(url=URL, retries=3, backoff=1.0):
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(backoff * (2 ** attempt))
    return False

if __name__ == "__main__":
    print("alive" if probe() else "down")
'''

TEMPLATES: list[Callable[[], str]] = [
    t_kubectl_deploy, t_docker_build, t_health_check_socket, t_slack_notify,
    t_rsync_backup, t_git_helper, t_prometheus_scrape, t_postgres_psql,
    t_internal_api_post, t_setup_py_legit, t_argparse_subcommand,
    t_eval_safe_expr, t_getattr_dispatch, t_base64_encode_legit,
    t_signal_handler, t_celery_task, t_threadpool_subprocess,
    t_systemd_journal, t_aws_boto_legit, t_health_check_http,
]

def generate(out_dir: Path, n: int = 800) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for i in range(n):
        template = random.choice(TEMPLATES)
        code = template()
        rec_id = f"benign_amb_{i:05d}"
        path = out_dir / f"{rec_id}.py"
        path.write_text(code)
        records.append({
            "id": rec_id,
            "path": str(path),
            "label": 0,
            "label_name": "benign",
            "template": template.__name__,
            "obfuscation": None,
            "source": "ambiguous_benign",
        })
    return records

if __name__ == "__main__":
    out = Path(__file__).resolve().parents[2] / "data" / "raw" / "benign_ambiguous"
    n = 800
    records = generate(out, n=n)
    manifest = out.parent.parent / "splits" / "benign_ambiguous_manifest.jsonl"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} ambiguous-benign scripts to {out}")
    print(f"manifest at {manifest}")
