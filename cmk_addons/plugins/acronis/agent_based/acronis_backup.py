#!/usr/bin/env python3
"""Checks for the data of the Acronis Cyber Protect Cloud special agent.

acronis_backup          one service per machine (piggyback): did the backup run cleanly?
acronis_backup_summary  one service on the host of the special agent
"""

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    check_levels,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    render,
    Result,
    Service,
    State,
    StringTable,
)

# The rule has one block of settings per service. What a rule does not set
# keeps the value given here.
_MACHINE_DEFAULTS: Mapping[str, Any] = {
    "age_levels": ("fixed", (129600.0, 259200.0)),  # 36 hours, 3 days
    "state_warning": int(State.WARN),
    "state_cancelled": int(State.WARN),
    "state_no_plan": int(State.CRIT),
}
_SUMMARY_DEFAULTS: Mapping[str, Any] = {
    "levels_with_plan": ("no_levels", None),
    "levels_without_plan": ("no_levels", None),
    "required_machines": [],
    "state_missing": int(State.CRIT),
}


def _settings(
    params: Mapping[str, Any], block: str, defaults: Mapping[str, Any]
) -> Mapping[str, Any]:
    # Versions 1.3.0 and 1.3.1 stored the settings side by side instead of in blocks.
    side_by_side = {key: params[key] for key in defaults if key in params}
    return {**defaults, **side_by_side, **params.get(block, {})}


# .
#   .--machine-------------------------------------------------------------.


@dataclass(frozen=True)
class Policy:
    type: str
    last_run: float | None
    last_success_run: float | None
    next_run: float | None


@dataclass(frozen=True)
class Run:
    plan: str
    result: str
    completed_at: float | None
    message: str


@dataclass
class Machine:
    names: list[str] = field(default_factory=list)
    plans: list[str] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    runs: list[Run] = field(default_factory=list)


def parse_acronis_backup(string_table: StringTable) -> Machine | None:
    """One line per Acronis resource. Several resources can map to the same host,
    for example a machine that is registered both with an agent and as a VM."""
    machine = Machine()
    for line in string_table:
        raw = json.loads(line[0])
        machine.names.append(f"{raw.get('name')} ({raw.get('type')})")
        machine.plans.extend(p for p in raw.get("plans", []) if p not in machine.plans)
        machine.policies.extend(
            Policy(
                type=str(p.get("type")),
                last_run=p.get("last_run"),
                last_success_run=p.get("last_success_run"),
                next_run=p.get("next_run"),
            )
            for p in raw.get("policies", [])
        )
        machine.runs.extend(
            Run(
                plan=str(r.get("plan") or ""),
                result=str(r.get("result")),
                completed_at=r.get("completed_at"),
                message=str(r.get("message") or ""),
            )
            for r in raw.get("runs", [])
        )
    return machine if machine.names else None


agent_section_acronis_backup = AgentSection(
    name="acronis_backup",
    parse_function=parse_acronis_backup,
)


def discover_acronis_backup(section: Machine) -> DiscoveryResult:
    if section.policies:
        yield Service()


_RESULT_TEXT = {
    "ok": "completed without warnings",
    "warning": "completed with warnings",
    "error": "failed",
    "cancelled": "was cancelled",
    "abandoned": "was abandoned",
    "timedout": "timed out",
}


def _run_state(result: str, params: Mapping[str, Any]) -> State:
    if result == "ok":
        return State.OK
    if result == "warning":
        return State(params["state_warning"])
    if result == "cancelled":
        return State(params["state_cancelled"])
    return State.CRIT


def _describe_run(run: Run) -> str:
    text = f"Plan '{run.plan}' " if run.plan else "Backup "
    text += _RESULT_TEXT.get(run.result, f"ended with result '{run.result}'")
    if run.completed_at:
        text += f" at {render.datetime(run.completed_at)}"
    if run.message:
        text += f": {run.message}"
    return text


def _check_runs(runs: Sequence[Run], params: Mapping[str, Any]) -> CheckResult:
    if all(run.result == "ok" for run in runs):
        newest = max((run.completed_at or 0.0 for run in runs), default=0.0)
        summary = (
            "Last run completed without warnings"
            if len(runs) == 1
            else f"Last runs of all {len(runs)} plans completed without warnings"
        )
        if newest:
            summary += (
                f" (latest at {render.datetime(newest)})"
                if len(runs) > 1
                else (f" at {render.datetime(newest)}")
            )
        yield Result(state=State.OK, summary=summary)
    for run in runs:
        state = _run_state(run.result, params)
        if run.result == "ok":
            yield Result(state=state, notice=_describe_run(run))
        else:  # shown in the summary even if the rule rates it as OK
            yield Result(state=state, summary=_describe_run(run))


def _check_last_runs_by_time(policies: Sequence[Policy]) -> CheckResult:
    """Fallback if Acronis reports no finished run within the evaluated period."""
    failed = [
        p
        for p in policies
        if p.last_run is not None
        and (p.last_success_run is None or p.last_run > p.last_success_run + 60)
    ]
    if failed:
        newest = max(p.last_run or 0.0 for p in failed)
        yield Result(
            state=State.CRIT,
            summary=f"Last run at {render.datetime(newest)} was not successful",
        )
    else:
        yield Result(state=State.OK, summary="No finished run within the evaluated period")


def check_acronis_backup(params: Mapping[str, Any], section: Machine) -> CheckResult:
    params = _settings(params, "machine", _MACHINE_DEFAULTS)
    if not section.policies:
        yield Result(
            state=State(params["state_no_plan"]),
            summary="No backup plan is applied to this machine",
        )
        return

    # Acronis counts a run with warnings as successful: it did create a backup.
    last_success = max(
        *(p.last_success_run or 0.0 for p in section.policies),
        *(r.completed_at or 0.0 for r in section.runs if r.result in ("ok", "warning")),
        0.0,
    )
    if last_success:
        yield from check_levels(
            max(time.time() - last_success, 0.0),
            levels_upper=params["age_levels"],
            metric_name="backup_age",
            render_func=render.timespan,
            label="Time since last successful backup",
        )
    else:
        yield Result(state=State.CRIT, summary="No successful backup so far")

    if section.runs:
        yield from _check_runs(section.runs, params)
    else:
        yield from _check_last_runs_by_time(section.policies)

    if section.plans:
        yield Result(state=State.OK, notice=f"Protection plans: {', '.join(section.plans)}")
    if next_runs := [p.next_run for p in section.policies if p.next_run]:
        yield Result(state=State.OK, notice=f"Next run: {render.datetime(min(next_runs))}")
    yield Result(state=State.OK, notice=f"Acronis resource: {', '.join(section.names)}")


check_plugin_acronis_backup = CheckPlugin(
    name="acronis_backup",
    service_name="Acronis Backup",
    discovery_function=discover_acronis_backup,
    check_function=check_acronis_backup,
    check_ruleset_name="acronis_backup",
    check_default_parameters={},
)

# .
#   .--summary-------------------------------------------------------------.


def parse_acronis_backup_summary(string_table: StringTable) -> Mapping[str, Any] | None:
    return json.loads(string_table[0][0]) if string_table else None


agent_section_acronis_backup_summary = AgentSection(
    name="acronis_backup_summary",
    parse_function=parse_acronis_backup_summary,
)


def discover_acronis_backup_summary(section: Mapping[str, Any]) -> DiscoveryResult:
    yield Service()


def _check_required_machines(
    params: Mapping[str, Any], protected: Sequence[str], unprotected: Sequence[str]
) -> CheckResult:
    """Machines that must have a backup plan, compared by name without regard to case."""
    required = sorted({name.strip().lower() for name in params["required_machines"]} - {""})
    if not required:
        return
    with_plan = {name.lower() for name in protected}
    without_plan = {name.lower() for name in unprotected}
    no_plan = [name for name in required if name in without_plan and name not in with_plan]
    unknown = [name for name in required if name not in with_plan | without_plan]
    state = State(params["state_missing"])
    if no_plan:
        yield Result(state=state, summary=f"Required but without backup plan: {', '.join(no_plan)}")
    if unknown:
        yield Result(state=state, summary=f"Required but unknown to Acronis: {', '.join(unknown)}")
    if not (no_plan or unknown):
        yield Result(
            state=State.OK,
            summary=f"All {len(required)} required machines have a backup plan",
        )


def _render_count(value: float) -> str:
    return f"{value:.0f}"


def check_acronis_backup_summary(
    params: Mapping[str, Any], section: Mapping[str, Any]
) -> CheckResult:
    params = _settings(params, "summary", _SUMMARY_DEFAULTS)
    protected = section.get("protected", [])
    unprotected = section.get("unprotected", [])
    yield from check_levels(
        len(protected),
        levels_lower=params["levels_with_plan"],
        metric_name="acronis_machines_with_plan",
        render_func=_render_count,
        label="Machines with backup plan",
    )
    yield from check_levels(
        len(unprotected),
        levels_upper=params["levels_without_plan"],
        metric_name="acronis_machines_without_plan",
        render_func=_render_count,
        label="Without backup plan",
    )

    days = section.get("lookback_hours", 0) / 24
    backup_runs = section.get("backup_runs", 0)
    if protected and not backup_runs:
        # Either nothing ran at all, or the activities of this tenant look different
        # from what the agent expects. In both cases somebody should have a look.
        yield Result(
            state=State.WARN,
            summary=f"No finished backup run found in the last {days:.0f} days",
            details=f"Finished activities of any kind in this period: "
            f"{section.get('activities', 0)}",
        )
    else:
        yield Result(
            state=State.OK,
            summary=f"Finished backup runs in the last {days:.0f} days: {backup_runs}",
        )

    yield from _check_required_machines(params, protected, unprotected)

    if protected:
        yield Result(state=State.OK, notice=f"With backup plan: {', '.join(protected)}")
    if unprotected:
        yield Result(state=State.OK, notice=f"Without backup plan: {', '.join(unprotected)}")


check_plugin_acronis_backup_summary = CheckPlugin(
    name="acronis_backup_summary",
    service_name="Acronis Backup Summary",
    discovery_function=discover_acronis_backup_summary,
    check_function=check_acronis_backup_summary,
    check_ruleset_name="acronis_backup",  # one rule set for both services
    check_default_parameters={},
)
