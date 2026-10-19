import sys
from cmk_addons.plugins.acronis.agent_based import acronis_backup as p
from cmk.agent_based.v2 import Result, Metric

host, sections = None, {}
for line in open(sys.argv[1]).read().splitlines():
    if line.startswith("<<<<"):
        host = line[4:-4] or None
    elif line.startswith("<<<"):
        name = line[3:-3].split(":")[0]
    else:
        sections.setdefault((host, name), []).append([line])

params = {}
for (host, name), table in sorted(sections.items(), key=lambda kv: str(kv[0])):
    if name == "acronis_backup_summary":
        sec = p.parse_acronis_backup_summary(table); disc = list(p.discover_acronis_backup_summary(sec))
        res = list(p.check_acronis_backup_summary({}, sec))
    else:
        sec = p.parse_acronis_backup(table); disc = list(p.discover_acronis_backup(sec))
        res = list(p.check_acronis_backup(params, sec))
    results = [r for r in res if isinstance(r, Result)]
    state = max((r.state for r in results), key=lambda s: {0:0,1:1,3:2,2:3}[int(s)])
    print(f"\n[{host or 'acronis (agent host)'}] discovered={bool(disc)} => {state.name}")
    print("  summary:", ", ".join(r.summary for r in results if r.summary))
    for r in results:
        if r.details and r.details != r.summary: print("  detail :", r.details)
    for m in res:
        if isinstance(m, Metric): print("  metric :", m.name, round(m.value), m.levels)
