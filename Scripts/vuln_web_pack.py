#!/usr/bin/env python3
"""
vuln_web_pack.py - DELIBERATELY VULNERABLE multi-bug practice target (stdlib only).

One server, four classic A/D web bugs, each hiding its own flag:

  /ping?host=<x>     Command Injection   -> FLAG{c0mm4nd_1nj3ct10n_pwn}   (in cmdi_flag.txt)
  /file?name=<x>     Path Traversal/LFI  -> FLAG{tr4v3rs3_th3_p4th}       (in lfi_flag.txt)
  /profile?id=<n>    IDOR / access ctrl  -> FLAG{1d0r_r34d_4ny_us3r}      (admin record id=2)
  /render?name=<x>   SSTI (eval-based)   -> FLAG{t3mpl4t3_1nj3ct10n_rce}  (in ssti_flag.txt)

Run:
    python3 vuln_web_pack.py            # http://0.0.0.0:5001
Attack each with its exploit file in practice/ (exploit_cmdi.py, etc.)

DO NOT deploy anywhere real - intentionally insecure.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))

# --- set up the planted flags on startup ---
FLAGS = {
    "cmdi_flag.txt": "FLAG{c0mm4nd_1nj3ct10n_pwn}",
    "lfi_flag.txt":  "FLAG{tr4v3rs3_th3_p4th}",
    "ssti_flag.txt": "FLAG{t3mpl4t3_1nj3ct10n_rce}",
}
for fn, val in FLAGS.items():
    with open(os.path.join(HERE, fn), "w") as f:
        f.write(val + "\n")

# IDOR data store: user 2 is the admin whose record holds the flag
USERS = {
    "1": {"name": "alice", "note": "hello"},
    "2": {"name": "admin", "note": "FLAG{1d0r_r34d_4ny_us3r}"},
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode(errors="replace"))

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if u.path == "/ping":
            host = q.get("host", ["127.0.0.1"])[0]
            # !!! VULN: user input in a shell command !!!
            cmd = f"ping -c 1 {host}"
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True,
                                     timeout=5, text=True)
                self._send(200, f"<pre>{out.stdout}{out.stderr}</pre>")
            except Exception as e:
                self._send(500, f"err: {e}")

        elif u.path == "/file":
            name = q.get("name", ["readme.txt"])[0]
            # !!! VULN: no path confinement !!!
            try:
                with open(os.path.join(HERE, name)) as f:
                    self._send(200, f.read())
            except Exception as e:
                self._send(404, f"not found: {e}")

        elif u.path == "/profile":
            uid = q.get("id", ["1"])[0]
            # !!! VULN: no ownership/auth check -> IDOR !!!
            user = USERS.get(uid)
            self._send(200, f"{user}" if user else "no such user")

        elif u.path == "/render":
            name = q.get("name", ["guest"])[0]
            # !!! VULN: user input evaluated as a template expression !!!
            # mimics Jinja2 {{ ... }} SSTI; here backed by eval()
            try:
                rendered = name
                while "{{" in rendered and "}}" in rendered:
                    s = rendered.index("{{"); e = rendered.index("}}")
                    expr = rendered[s + 2:e]
                    rendered = rendered[:s] + str(eval(expr)) + rendered[e + 2:]
                self._send(200, f"Hello, {rendered}")
            except Exception as ex:
                self._send(500, f"template error: {ex}")

        else:
            self._send(200, "endpoints: /ping /file /profile /render")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("serving on http://0.0.0.0:5001  (Ctrl-C to stop)")
    ThreadingHTTPServer(("0.0.0.0", 5001), Handler).serve_forever()
