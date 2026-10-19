"""Replays recorded answers of the Acronis API, paged like the real service."""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

PORT, RES, ACT = int(sys.argv[1]), sys.argv[2], sys.argv[3]
DATA = {"/api/resource_management/v4/resource_statuses": json.load(open(RES))["items"],
        "/api/task_manager/v2/activities": json.load(open(ACT))["items"]}
PAGE = 100

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        body = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self._send(200, {"access_token": "replay", "expires_on": 4102444800, "token_type": "bearer"})
    def do_GET(self):
        url = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(url.query).items()}
        items = DATA.get(url.path)
        if items is None or self.headers.get("Authorization") != "Bearer replay":
            return self._send(404, {"error": "unknown"})
        if "after" in q:
            assert set(q) == {"limit", "after"}, q
        start = int(q.get("after", 0)); page = items[start:start + PAGE]
        answer = {"items": page, "size": len(page)}
        if start + PAGE < len(items):
            answer["paging"] = {"cursors": {"after": str(start + PAGE)}}
        self._send(200, answer)

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
