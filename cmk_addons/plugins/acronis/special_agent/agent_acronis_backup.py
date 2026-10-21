#!/usr/bin/env python3
"""agent_acronis_backup

Checkmk special agent for Acronis Cyber Protect Cloud.

Fetches the protection status of all machines and the results of the finished
runs of the backup plans from the Acronis API and writes them as piggyback
data, one section per machine.
"""

import argparse
import io
import json
import os
import re
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, UTC
from email.utils import parsedate_to_datetime
from typing import Any

import requests

from cmk.password_store.v1_unstable import parser_add_secret_option, resolve_secret_option
from cmk.server_side_programs.v1_unstable import report_agent_crashes, Storage

__version__ = "1.4.1"

AGENT = "acronis_backup"
USER_AGENT = f"checkmk-special-{AGENT}-{__version__}"
SECRET_OPTION = "client-secret"

TIMEOUT = 30  # seconds per request
RESOURCE_PAGE_SIZE = 200
ACTIVITY_PAGE_SIZE = 500
MAX_PAGES = 100  # hard stop against endless paging
TOKEN_MIN_REMAINING = 300  # seconds a cached token must still be valid

# Rate limiting (HTTP 429) and temporary server errors are retried, honouring
# Retry-After. All waiting of one run together stays below RETRY_BUDGET so the
# agent finishes well within the timeout of the Checkmk fetcher.
RETRY_STATUS = frozenset({429, 502, 503, 504})
MAX_RETRIES = 3  # per request
RETRY_BUDGET = 30.0  # seconds of waiting per run
RETRY_DEFAULT_DELAY = 5.0  # seconds, doubled per attempt, when Retry-After is missing

# The last good output is kept and handed out again (marked as cached) when the
# API cannot be read, so one failed run does not turn the services stale.
OUTPUT_CACHE_KEY = "output"
DEFAULT_MAX_CACHE_AGE = 1800  # seconds

# Resources that are machines in the sense of the Acronis console ("Devices").
MACHINE_TYPE_PREFIXES = ("resource.machine", "resource.virtual_machine")
MESSAGE_MAX_LENGTH = 400

JSON = Mapping[str, Any]


class AcronisError(Exception):
    pass


def parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    prog, description = __doc__.split("\n\n", maxsplit=1)
    parser = argparse.ArgumentParser(
        prog=prog, description=description, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--debug", action="store_true", help="Raise exceptions with traceback")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print what was fetched to stderr"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Data center URL of the Acronis tenant, e.g. https://eu2-cloud.acronis.com",
    )
    parser.add_argument("--client-id", required=True, help="ID of the Acronis API client")
    parser_add_secret_option(
        parser, long=f"--{SECRET_OPTION}", help="Secret of the Acronis API client", required=True
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=72,
        help="Evaluate the runs that finished within this period (default: 72)",
    )
    parser.add_argument(
        "--hostname",
        default="acronis",
        help="Checkmk host this agent runs for (namespace of the token cache)",
    )
    parser.add_argument(
        "--keep-case", action="store_true", help="Do not lower-case the piggyback host names"
    )
    parser.add_argument(
        "--strip-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Cut this domain off the piggyback host names (can be given several times)",
    )
    parser.add_argument(
        "--no-token-cache",
        action="store_true",
        help="Request a new access token on every run",
    )
    parser.add_argument(
        "--max-cache-age",
        type=int,
        default=DEFAULT_MAX_CACHE_AGE,
        metavar="SECONDS",
        help="If the API cannot be read, output the last good result if it is not older "
        f"than this, marked as cached (default: {DEFAULT_MAX_CACHE_AGE}, 0 disables)",
    )
    return parser.parse_args(argv)


# .
#   .--API-----------------------------------------------------------------.


class AcronisAPI:
    def __init__(self, url: str, client_id: str, client_secret: str, storage: Storage | None):
        self._base = url.rstrip("/") + "/api"
        self._client_id = client_id
        self._client_secret = client_secret
        self._storage = storage
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        self._token_is_cached = False
        self._retry_budget = RETRY_BUDGET

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """One HTTP request, retried on rate limiting and temporary server errors."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self._session.request(method, url, timeout=TIMEOUT, **kwargs)
            except requests.RequestException as exc:
                raise AcronisError(f"Cannot reach Acronis ({url}): {exc}") from exc
            if response.status_code not in RETRY_STATUS or attempt == MAX_RETRIES:
                return response
            delay = _retry_delay(response, attempt)
            if delay > self._retry_budget:
                return response  # waiting longer would risk the fetcher timeout
            self._retry_budget -= delay
            time.sleep(delay)
        return response  # not reached, keeps type checkers happy

    # Acronis asks integrations to reuse the access token (valid for two hours)
    # instead of issuing a new one for every sequence of calls.
    def _read_cached_token(self) -> str | None:
        if self._storage is None:
            return None
        try:
            cached = json.loads(self._storage.read("token", "{}"))
            if (
                cached["client_id"] == self._client_id
                and cached["base"] == self._base
                and cached["expires_on"] - time.time() > TOKEN_MIN_REMAINING
            ):
                return str(cached["access_token"])
        except (RuntimeError, ValueError, KeyError, TypeError):
            pass
        return None

    def _write_cached_token(self, token: str, expires_on: float) -> None:
        if self._storage is None:
            return
        try:
            self._storage.write(
                "token",
                json.dumps(
                    {
                        "client_id": self._client_id,
                        "base": self._base,
                        "access_token": token,
                        "expires_on": expires_on,
                    }
                ),
            )
        except (RuntimeError, OSError):
            pass  # caching is an optimization only

    def login(self, *, force: bool = False) -> None:
        if not force and (token := self._read_cached_token()):
            self._token_is_cached = True
        else:
            token = self._request_token()
            self._token_is_cached = False
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _request_token(self) -> str:
        response = self._send(
            "POST",
            f"{self._base}/2/idp/token",
            auth=(self._client_id, self._client_secret),
            data={"grant_type": "client_credentials"},
        )
        if response.status_code != 200:
            raise AcronisError(
                f"Acronis login failed (HTTP {response.status_code}): {_shorten(response.text)}"
            )
        data = response.json()
        token = str(data["access_token"])
        self._write_cached_token(token, float(data.get("expires_on", 0)))
        return token

    def _get(self, path: str, params: Mapping[str, str | int]) -> JSON:
        for attempt in (1, 2):
            response = self._send("GET", f"{self._base}{path}", params=params)
            # A cached token may have been revoked: get a fresh one once.
            if response.status_code == 401 and self._token_is_cached and attempt == 1:
                self.login(force=True)
                continue
            break
        if response.status_code != 200:
            raise AcronisError(
                f"Request to {path} failed (HTTP {response.status_code}): {_shorten(response.text)}"
            )
        data = response.json()
        if not isinstance(data, dict):
            raise AcronisError(f"Unexpected answer from {path}: {_shorten(response.text)}")
        return data

    def _paged(self, path: str, params: Mapping[str, str | int], limit: int) -> Iterator[JSON]:
        """Yield all items. The page token encodes the query of the first request,
        so the following requests carry only the limit and the token."""
        query: Mapping[str, str | int] = {**params, "limit": limit}
        for _page in range(MAX_PAGES):
            data = self._get(path, query)
            items = data.get("items") or []
            yield from items
            cursors = (data.get("paging") or {}).get("cursors") or data.get("cursors") or {}
            after = cursors.get("after")
            if not after or not items:
                return
            query = {"limit": limit, "after": after}
        sys.stderr.write(f"Stopped reading {path} after {MAX_PAGES} pages\n")

    def resource_statuses(self) -> Iterator[JSON]:
        yield from self._paged("/resource_management/v4/resource_statuses", {}, RESOURCE_PAGE_SIZE)

    def completed_activities(self, since: float) -> Iterator[JSON]:
        """Finished activities, newest first, back to the time 'since'."""
        params = {
            "state": "completed",
            "completedAt": f"gt({_iso(since)})",
            "order": "desc(completedAt)",
        }
        path = "/task_manager/v2/activities"
        for activity in self._paged(path, params, ACTIVITY_PAGE_SIZE):
            completed = _epoch(activity.get("completedAt"))
            if completed is not None and completed < since:
                return  # newest first: everything from here on is too old
            yield activity


# .
#   .--helpers-------------------------------------------------------------.


def _retry_delay(response: requests.Response, attempt: int) -> float:
    """Seconds to wait before the next attempt: Retry-After (seconds or HTTP date)
    if the server sends it, otherwise exponential backoff."""
    value = response.headers.get("Retry-After", "").strip()
    if value:
        try:
            return max(1.0, float(value))
        except ValueError:
            pass
        try:
            return max(1.0, parsedate_to_datetime(value).timestamp() - time.time())
        except (TypeError, ValueError, IndexError, OverflowError):
            pass
    return RETRY_DEFAULT_DELAY * 2**attempt


def _shorten(text: object, length: int = MESSAGE_MAX_LENGTH) -> str:
    line = " ".join(str(text).split())
    return line if len(line) <= length else line[: length - 3] + "..."


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value: object) -> float | None:
    """Convert an RFC 3339 time stamp of the API ('2021-02-03T15:00:48Z') to epoch."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    if parsed.year < 1971:  # "never" is reported as a zero date
        return None
    return parsed.timestamp()


def piggyback_name(name: str, *, lowercase: bool, strip_domains: Sequence[str]) -> str:
    name = name.strip().rstrip(".")
    for domain in strip_domains:
        suffix = "." + domain.strip(".").lower()
        if name.lower().endswith(suffix) and len(name) > len(suffix):
            name = name[: -len(suffix)]
            break
    if lowercase:
        name = name.lower()
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


# Where the readable text of an error or warning object is found, best first.
_TEXT_PATHS: Sequence[Sequence[str]] = (
    ("context", "effect_str"),
    ("context", "cause_str"),
    ("context", "_src", "text"),
    ("debug", "msg"),
    ("message",),
    ("text",),
    ("reason",),
    ("code",),
)


def _message(detail: object) -> str:
    """Readable text of one error or warning object of an activity result."""
    if isinstance(detail, str):
        return detail.strip()
    for path in _TEXT_PATHS:
        value = detail
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def result_messages(result: JSON) -> list[str]:
    details: list[object] = [result.get("error")]
    warnings = result.get("warnings")
    details.extend(warnings if isinstance(warnings, list) else [warnings])
    return [message for message in map(_message, details) if message]


def is_machine(resource: JSON) -> bool:
    return str((resource.get("context") or {}).get("type", "")).startswith(MACHINE_TYPE_PREFIXES)


def is_backup_policy(policy_type: object) -> bool:
    """'policy.backup.machine' and the like, but not e.g. the scanning of backups."""
    name = str(policy_type).lower()
    return name == "backup" or name.startswith(("policy.backup", "backup."))


# .
#   .--data----------------------------------------------------------------.


def machine_record(resource: JSON) -> dict[str, Any]:
    context = resource.get("context") or {}
    aggregate = resource.get("aggregate") or {}
    names = aggregate.get("names") or ""
    plans = names if isinstance(names, list) else [n for n in str(names).split(";") if n]
    # Acronis keeps the dates of the last run after a plan was revoked.
    applied = aggregate.get("status") != "no_policies_applied"
    return {
        "id": context.get("id"),
        "name": context.get("user_defined_name") or context.get("name") or "",
        "type": context.get("type"),
        "status": aggregate.get("status"),
        "plans": plans,
        "policies": [
            {
                "type": policy.get("type"),
                "last_run": _epoch(policy.get("last_run")),
                "last_success_run": _epoch(policy.get("last_success_run")),
                "next_run": _epoch(policy.get("next_run") or policy.get("next_run_time")),
            }
            for policy in resource.get("policies") or []
            if applied and is_backup_policy(policy.get("type"))
        ],
        "runs": [],
    }


_SEVERITY = {"ok": 0, "warning": 1, "cancelled": 2}  # everything else is a failure


def _severity(code: str) -> int:
    return _SEVERITY.get(code, 3)


def latest_runs(
    activities: Sequence[JSON],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    """Result of the most recent finished run of every backup plan, per resource.

    One run of a plan is one task with many activities, and they belong to
    different resources: the run as a whole to the machine of the agent, the
    backup of a virtual machine to that VM. So the result of a run for a
    resource is the worst result of the activities of the run that belong to
    it. The activities must be sorted newest first. The key of the returned
    runs is the lower-cased ID of the resource.
    """
    backup = [a for a in activities if is_backup_policy((a.get("policy") or {}).get("type"))]
    # A run is finished when its top-level activity is: skip the ones in progress.
    finished = {a["taskId"] for a in backup if a.get("taskId") and not a.get("parentActivityId")}
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for activity in backup:
        task_id = activity.get("taskId")
        resource_id = str((activity.get("resource") or {}).get("id") or "").lower()
        if task_id not in finished or not resource_id:
            continue
        policy = activity.get("policy") or {}
        run = latest.setdefault(
            (resource_id, str(policy.get("id") or policy.get("name"))),
            {
                "task": task_id,
                "plan": str(policy.get("name") or ""),
                "result": "ok",
                "completed_at": _epoch(activity.get("completedAt")),
                "step_messages": [],
                "run_messages": [],
            },
        )
        if run["task"] != task_id:
            continue  # an older run of the same plan
        result = activity.get("result") or {}
        code = str(result.get("code") or "unknown")
        if _severity(code) > _severity(run["result"]):
            run["result"] = code
        if code != "ok":
            # The top-level activity only says "completed with warnings".
            target = run["step_messages" if activity.get("parentActivityId") else "run_messages"]
            target.extend(m for m in result_messages(result) if m not in target)

    runs: dict[str, list[dict[str, Any]]] = {}
    for (resource_id, _policy), run in latest.items():
        runs.setdefault(resource_id, []).append(
            {
                "plan": run["plan"],
                "result": run["result"],
                "completed_at": run["completed_at"],
                "message": _shorten("; ".join(run["step_messages"] or run["run_messages"])),
            }
        )
    return runs, {"activities": len(activities), "backup_runs": len(finished)}


def collect(api: AcronisAPI, since: float) -> tuple[list[dict[str, Any]], dict[str, int]]:
    machines = [machine_record(r) for r in api.resource_statuses() if is_machine(r)]
    runs, statistics = latest_runs(list(api.completed_activities(since)))
    for machine in machines:
        machine["runs"] = runs.get(str(machine["id"]).lower(), [])
    return machines, statistics


def render_sections(
    machines: Sequence[Mapping[str, Any]],
    statistics: Mapping[str, Any],
    args: argparse.Namespace,
) -> str:
    out = io.StringIO()
    by_host: dict[str, list[Mapping[str, Any]]] = {}
    for machine in machines:
        host = piggyback_name(
            machine["name"], lowercase=not args.keep_case, strip_domains=args.strip_domain
        )
        if host:
            by_host.setdefault(host, []).append(machine)

    summary = {
        **statistics,
        "lookback_hours": args.lookback_hours,
        "protected": sorted(h for h, ms in by_host.items() if any(m["policies"] for m in ms)),
        "unprotected": sorted(h for h, ms in by_host.items() if not any(m["policies"] for m in ms)),
    }
    out.write("<<<acronis_backup_summary:sep(0)>>>\n")
    out.write(json.dumps(summary, sort_keys=True) + "\n")

    for host, host_machines in sorted(by_host.items()):
        out.write(f"<<<<{host}>>>>\n")
        out.write("<<<acronis_backup:sep(0)>>>\n")
        for machine in host_machines:
            out.write(json.dumps(machine, sort_keys=True) + "\n")
        out.write("<<<<>>>>\n")
    return out.getvalue()


# .
#   .--output cache--------------------------------------------------------.

# Section headers, but not the piggyback headers <<<<host>>>> / <<<<>>>>.
_SECTION_HEADER = re.compile(r"^<<<(?!<)(.+)>>>$", re.MULTILINE)


def mark_cached(output: str, created: float, max_age: int) -> str:
    """Add the cached(...) option to every section header, so Checkmk shows the
    age of the data and treats it as stale once it is older than max_age."""
    option = f":cached({int(created)},{max_age})"
    return _SECTION_HEADER.sub(lambda m: f"<<<{m.group(1)}{option}>>>", output)


def write_output_cache(storage: Storage, output: str) -> None:
    try:
        storage.write(OUTPUT_CACHE_KEY, json.dumps({"created": time.time(), "output": output}))
    except (RuntimeError, OSError) as exc:
        sys.stderr.write(f"Cannot write output cache: {exc}\n")  # optimization only


def read_output_cache(storage: Storage, max_age: int) -> str | None:
    """The last good output, marked as cached, if it is not older than max_age."""
    if max_age <= 0:
        return None
    try:
        cached = json.loads(storage.read(OUTPUT_CACHE_KEY, "{}"))
        created, output = float(cached["created"]), str(cached["output"])
    except (RuntimeError, OSError, ValueError, KeyError, TypeError):
        return None
    if not 0 <= time.time() - created <= max_age:
        return None
    return mark_cached(output, created, max_age)


# .


def agent_acronis_backup_main(args: argparse.Namespace) -> int:
    os.umask(0o077)  # token and output cache must not be readable by others
    storage = Storage(AGENT, args.hostname)
    api = AcronisAPI(
        args.url,
        args.client_id,
        resolve_secret_option(args, SECRET_OPTION.replace("-", "_")).reveal(),
        None if args.no_token_cache else storage,
    )
    try:
        api.login()
        machines, statistics = collect(api, time.time() - args.lookback_hours * 3600)
    except AcronisError as exc:
        if args.debug:
            raise
        sys.stderr.write(f"{exc}\n")
        if (cached := read_output_cache(storage, args.max_cache_age)) is None:
            return 1
        # A temporary failure (e.g. rate limiting): hand out the last good data,
        # its age is shown in the services.
        sys.stdout.write(cached)
        return 0

    if args.verbose:
        sys.stderr.write(
            f"{len(machines)} machines, {statistics['activities']} finished activities in the "
            f"last {args.lookback_hours} h, {statistics['backup_runs']} finished backup runs\n"
        )
    output = render_sections(machines, statistics, args)
    if args.max_cache_age > 0:
        write_output_cache(storage, output)
    sys.stdout.write(output)
    return 0


@report_agent_crashes(AGENT, __version__)
def main() -> int:
    return agent_acronis_backup_main(parse_arguments(sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(main())
