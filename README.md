# Acronis Cyber Protect Cloud – Checkmk plugin

Version 1.4.0 · Checkmk 2.5.0 or later (Community Edition and up) · package name `acronis_backup`

Checks per machine whether the Acronis backup ran cleanly. A special agent reads the
Acronis Cyber Protect Cloud API and hands the data to the matching Checkmk hosts as
piggyback data.

## What you get

| Service | Host | Shows |
|---|---|---|
| **Acronis Backup** | every machine with a backup plan | result of the last run of each plan, age of the last successful backup |
| **Acronis Backup Summary** | the host the special agent runs on | number of machines with and without a backup plan, finished backup runs |

### Acronis Backup

| State | When (defaults) |
|---|---|
| OK | the last run of every plan finished without warnings, last successful backup younger than 36 hours |
| WARN | a last run finished with warnings or was cancelled, or the last successful backup is older than 36 hours |
| CRIT | a last run failed, was abandoned or timed out; last successful backup older than 3 days; never a successful backup; no backup plan applied any more |

- A run with warnings still counts as a successful backup for the age.
- The Acronis warning or error text is shown in the service output.
- Runs of application backups (SQL, Exchange) count for the machine of the agent.
- If no run finished within the evaluated period, the check falls back to the time stamps
  of the last run and the last successful run.

### Acronis Backup Summary

OK by default. It can alert on:

- too few machines with a backup plan,
- too many machines without a backup plan,
- listed machines that have no backup plan or are unknown to Acronis.

It goes WARN if machines have a plan but no backup run finished in the evaluated period.
Both counts are recorded as metrics.

## Requirements

- An API client in the Acronis management console (client ID, secret, data center URL,
  e.g. `https://eu2-cloud.acronis.com`).
- Outbound HTTPS from the Checkmk server to the data center.
- The machines exist as hosts in Checkmk under the name the agent derives from the Acronis
  machine name (see *Host names* below).

## Installation

Copy the package to the Checkmk server so that the site user can read it, then as the site
user:

```
mkp add /tmp/acronis_backup-1.4.0.mkp
mkp enable acronis_backup 1.4.0
```

`mkp add` prints `acronis_backup 1.4.0` on success. If it prints nothing, the file is not
readable for the site user (`chmod 644`), or run `mkp -d add …` to see the error.

Enabling a new version replaces the old one; existing rules stay.

## Setup

1. **Store the secret:** Setup → General → Passwords (optional, you can also enter it in
   the rule).
2. **Special agent rule:** Setup → Agents → Other integrations →
   *Acronis Cyber Protect Cloud*.
   - Data center URL, API client ID, API client secret.
   - *Evaluate finished runs of the last … days* (default 3, 1–31): should cover the
     longest gap between two scheduled runs.
   - *Remove these domains from the machine names*: e.g. `example.local`.
   - **Conditions → Explicit hosts: exactly one host.** A rule without this condition
     applies to every host, and every host then queries Acronis instead of its own agent.
3. **The host the rule runs on:**
   - a dedicated host, e.g. `acronis`, with *IP address family* set to **No IP**, **or**
   - an existing host such as the Checkmk server itself. Then set Properties → Monitoring
     agents → *Checkmk agent / API integrations* to **Configured API integrations and
     Checkmk agent**, otherwise it loses its normal services.
4. Activate changes, then run the service discovery on the agent host and on the machines.

Do not accept *vanished services* during this setup: if the conditions are wrong, the
normal services only look vanished.

### Host names

The agent turns an Acronis machine name into a piggyback host name like this:

1. remove a domain listed in the rule (`s-fs01.example.local` → `s-fs01`),
2. lower case (can be switched off in the rule),
3. replace characters other than letters, digits, `_ . -` by `_`.

Several Acronis resources with the same resulting name (e.g. a server registered with an
agent and as a Hyper-V VM) are combined into one service. The details of the summary
service list all names, which helps to find mismatches with Checkmk.

## Thresholds

Setup → Services → Service monitoring rules → **Acronis backup**. One rule for both
services, with two optional blocks:

**Backup of a machine** (service *Acronis Backup*)

| Setting | Default |
|---|---|
| Time since the last successful backup | WARN 36 h, CRIT 3 days |
| State if the last run finished with warnings | WARN |
| State if the last run was cancelled | WARN |
| State if no backup plan is applied any more | CRIT |

**Overview of all machines** (service *Acronis Backup Summary*)

| Setting | Default |
|---|---|
| Minimum number of machines with a backup plan | no levels |
| Maximum number of machines without a backup plan | no levels |
| Machines that must have a backup plan | empty |
| State if one of these machines has no backup plan | CRIT |

- A block counts as a whole: the first matching rule with the block ticked supplies all of
  its settings. Use separate rules for the machines and for the agent host.
- The maximum alerts when the count *reaches* the value: to tolerate 4 machines without a
  plan, set WARN to 5.
- Machines with only a weekly plan need age levels of about 8 / 9 days.

## Running the agent by hand

As the site user:

```
~/local/lib/python3/cmk_addons/plugins/acronis/libexec/agent_acronis_backup \
  --url https://eu2-cloud.acronis.com --client-id <id> --client-secret <secret> \
  --strip-domain example.local -v
```

| Option | Meaning |
|---|---|
| `--lookback-hours N` | evaluated period (default 72) |
| `--strip-domain D` | remove domain D from machine names, repeatable |
| `--keep-case` | do not lower-case the names |
| `--no-token-cache` | request a new access token on every run |
| `-v` | number of machines, activities and backup runs to stderr |
| `--debug` | show tracebacks |

Passing the secret on the command line makes it visible in the process list; use this only
for tests. Checkmk itself passes a reference to the password store.

## How it works

- Login: `POST /api/2/idp/token` (client credentials). The access token is cached between
  runs in the storage of the special agent (readable for the site user only) and renewed
  when it expires or is rejected.
- Machines and plans: `GET /api/resource_management/v4/resource_statuses` – resources of
  type `resource.machine*` and `resource.virtual_machine*`, policies `policy.backup*`.
- Run results: `GET /api/task_manager/v2/activities`, finished in the evaluated period,
  newest first. One run of a plan is one task with many activities; the result for a
  machine is the worst result of the activities of that run that belong to it. Runs still
  in progress are skipped.
- Paging uses the cursor of the API; the first request carries the filters, later ones only
  `limit` and `after`.

## Limitations

- The result of a plan that was removed from a machine stays in the evaluation until it is
  older than the evaluated period.
- Acronis does not document the structure of error objects; if no readable text is found,
  the error code is shown instead.
- The agent uses the password store and storage helpers of the Checkmk plugin API in
  version `v1_unstable`. A major Checkmk upgrade may require an update of the plugin.

## Files

```
cmk_addons/plugins/acronis/
├── agent_based/acronis_backup.py           checks and sections
├── checkman/acronis_backup                 man page
├── graphing/acronis_backup.py              metrics of the summary
├── libexec/agent_acronis_backup            entry point of the special agent
├── rulesets/check_parameters.py            rule "Acronis backup"
├── rulesets/special_agent.py               rule "Acronis Cyber Protect Cloud"
├── server_side_calls/acronis_backup.py     command line of the special agent
└── special_agent/agent_acronis_backup.py   the special agent
```

## Changelog

- **1.4.0** – Thresholds rule split into two blocks, settings shown below each other.
  Rules from 1.3.x are migrated.
- **1.3.0** – One rule for both services; minimum / maximum number of machines with and
  without a plan; metrics.
- **1.2.0** – Summary can alert on required machines without a backup plan.
- **1.1.0** – Results per plan from Acronis activities instead of tasks; resources with
  the same host name combined; list of domains to remove instead of a fixed switch.
- **1.0.0** – First version.
