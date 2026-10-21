"""Rate limiting and output cache of the special agent, against a fake Acronis API.

Runs without a Checkmk site: the Checkmk helper modules are stubbed.
    python3 -m pip install requests && python3 tests/test_rate_limit.py
"""
import json
import sys
import tempfile
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STORE = Path(tempfile.mkdtemp())


# --- stubs of the Checkmk plugin API ---------------------------------------
class Storage:
    def __init__(self, ident, host):
        self._dir = STORE / ident / host
        self._dir.mkdir(parents=True, exist_ok=True)

    def read(self, key, default):
        path = self._dir / key
        return path.read_text() if path.exists() else default

    def write(self, key, content):
        (self._dir / key).write_text(content)


class _Secret(str):
    def reveal(self):
        return str(self)


pw = types.ModuleType("cmk.password_store.v1_unstable")
pw.parser_add_secret_option = lambda p, long, help, required: p.add_argument(long, required=required)
pw.resolve_secret_option = lambda args, name: _Secret(getattr(args, name))
ssp = types.ModuleType("cmk.server_side_programs.v1_unstable")
ssp.Storage = Storage
ssp.report_agent_crashes = lambda *a: (lambda f: f)
for name in ("cmk", "cmk.password_store", "cmk.server_side_programs"):
    sys.modules[name] = types.ModuleType(name)
sys.modules[pw.__name__], sys.modules[ssp.__name__] = pw, ssp

from cmk_addons.plugins.acronis.special_agent import agent_acronis_backup as agent  # noqa: E402

# --- fake API: answers with 429 as long as STATE["throttle"] > 0 -----------
STATE = {"throttle": 0, "requests": 0}
RESOURCE = {
    "context": {"id": "M1", "type": "resource.machine", "name": "s-test01"},
    "aggregate": {"status": "ok", "names": "Daily"},
    "policies": [{"type": "policy.backup.machine", "last_run": "2026-10-21T01:00:00Z",
                  "last_success_run": "2026-10-21T01:00:00Z"}],
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(code)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _throttled(self):
        STATE["requests"] += 1
        if STATE["throttle"] > 0:
            STATE["throttle"] -= 1
            self._send(429, {"error": {"code": "tooManyRequests"}}, [("Retry-After", "1")])
            return True
        return False

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        if not self._throttled():
            self._send(200, {"access_token": "t", "expires_on": time.time() + 7200})

    def do_GET(self):
        if self._throttled():
            return
        items = [RESOURCE] if "resource_statuses" in self.path else []
        self._send(200, {"items": items})


server = HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{server.server_port}"


def run(*extra):
    import contextlib
    import io

    out, err = io.StringIO(), io.StringIO()
    argv = ["--url", URL, "--client-id", "id", "--client-secret", "s", "--hostname", "t", *extra]
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = agent.agent_acronis_backup_main(agent.parse_arguments(argv))
    return code, out.getvalue(), err.getvalue()


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label)
    if not condition:
        print(detail)
        sys.exit(1)


# 1. Two 429s are waited out (Retry-After: 1) and the run succeeds with fresh data.
STATE.update(throttle=2, requests=0)
code, out, err = run()
check("429 retried, run succeeds", code == 0 and "<<<<s-test01>>>>" in out, (code, out, err))
check("fresh data is not marked cached", "cached(" not in out)

# 2. API keeps refusing: the last good output is handed out, marked as cached.
agent.RETRY_BUDGET = 2.0
STATE.update(throttle=10_000)
code, out, err = run()
check("persistent 429 falls back to cache", code == 0 and "<<<<s-test01>>>>" in out)
check("summary header marked cached",
      "<<<acronis_backup_summary:sep(0):cached(" in out)
check("piggyback section marked cached", "<<<acronis_backup:sep(0):cached(" in out)
check("piggyback host headers untouched", "<<<<>>>>" in out and "<<<<s-test01" in out)
check("error still reported on stderr", "HTTP 429" in err)

# 3. Cache disabled: the failure is reported as before.
code, out, err = run("--max-cache-age", "0")
check("--max-cache-age 0 disables fallback", code == 1 and out == "")

# 4. Cache too old: the failure is reported.
cache = STORE / "acronis_backup" / "t" / "output"
data = json.loads(cache.read_text())
data["created"] -= 3600
cache.write_text(json.dumps(data))
code, out, err = run()
check("cache older than max age is not used", code == 1 and out == "")

# 5. Retry-After as HTTP date and missing header.
class R:
    def __init__(self, value):
        self.headers = {"Retry-After": value} if value is not None else {}

from email.utils import formatdate  # noqa: E402

check("Retry-After as HTTP date", 5 <= agent._retry_delay(R(formatdate(time.time() + 8, usegmt=True)), 0) <= 9)
check("backoff without Retry-After", agent._retry_delay(R(None), 2) == agent.RETRY_DEFAULT_DELAY * 4)
print("all tests passed")
