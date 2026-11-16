#!/usr/bin/env python3
"""
vuln_web.py - DELIBERATELY VULNERABLE practice target for exploit_sqli.py.

Uses only the Python standard library (no pip install needed) so it runs on the
pwnbox or anywhere. Mimics a planted A/D web service: /item?id=<n> with raw
string-built SQL. Run it, then attack it with exploit_sqli.py.

Run:
    python3 vuln_web.py
    # serves on http://0.0.0.0:5000

Attack:
    python3 ../exploit_sqli.py 127.0.0.1
    # expected:  [sqli] 127.0.0.1 -> FLAG{sql1_1s_th3_cl4ss1c}

DO NOT deploy this anywhere real - it is intentionally insecure.
"""
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def run_query(item_id):
    con = sqlite3.connect(":memory:")
    con.executescript(
        """
        CREATE TABLE items (id INTEGER, name TEXT, price TEXT);
        INSERT INTO items VALUES (1, 'Sticker', '3'), (2, 'Mug', '12');
        CREATE TABLE flags (flag TEXT);
        INSERT INTO flags VALUES ('FLAG{sql1_1s_th3_cl4ss1c}');
        """
    )
    # !!! THE VULNERABILITY: user input concatenated straight into the query !!!
    query = f"SELECT name, price FROM items WHERE id = '{item_id}'"
    return con.execute(query).fetchall()  # may raise -> error-based SQLi practice


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/item":
            item_id = parse_qs(parsed.query).get("id", ["1"])[0]
            try:
                rows = run_query(item_id)
            except Exception as e:
                self._send(500, f"SQL error: {e}")  # errors are reflected on purpose
                return
            body = "<br>".join(f"{n} - ${p}" for n, p in rows) or "no results"
            self._send(200, body)
        else:
            self._send(200, 'Try <a href="/item?id=1">/item?id=1</a>')

    def log_message(self, *a):
        pass  # quiet


if __name__ == "__main__":
    print("serving on http://0.0.0.0:5000  (Ctrl-C to stop)")
    ThreadingHTTPServer(("0.0.0.0", 5000), Handler).serve_forever()
