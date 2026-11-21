"""Send sample Vijil events to a PagerDuty integration, with no Phoenix or Vijil account.

    vijil-pagerduty test [--action trigger|acknowledge|resolve] [--dry-run]

Environment: PAGERDUTY_ROUTING_KEY, the integration key of the service under test.

trigger sends one Dome block event twice (same dedup key: PagerDuty opens one incident)
and one Diamond finding event. acknowledge and resolve act on both incidents.
The sample agent's trust domain is test.vijil.ai, so every sample incident names it as a test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from vijil_pagerduty import events

AGENT = "spiffe://test.vijil.ai/org/00000000-0000-4000-8000-000000000001/agent/00000000-0000-4000-8000-000000000002"
DOME = events.Reference(
    finding_id="00000000000000d1", category="dome_block", severity="error",
    agent=AGENT, trace_id="0000000000000000000000000000d0e1",
)
DIAMOND = events.Reference(
    finding_id="00000000-0000-4000-8000-0000000000f1", category="pii_leak", severity="warning",
    agent=AGENT, trace_id="0000000000000000000000000000d1a1",
)
DOME_KEY = events.dome_dedup_key(AGENT, "dome-enterprise")
DIAMOND_KEY = events.diamond_dedup_key(DIAMOND.finding_id)


def sample_events(action: str) -> list[dict]:
    if action == "trigger":
        dome = events.trigger(DOME, DOME_KEY, source="vijil-dome", component="dome")
        return [dome, dome, events.trigger(DIAMOND, DIAMOND_KEY, source="vijil-diamond", component="diamond")]
    build = events.acknowledge if action == "acknowledge" else events.resolve
    return [build(DOME_KEY), build(DIAMOND_KEY)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vijil-pagerduty test", description=__doc__.split("\n")[0])
    ap.add_argument("--action", choices=["trigger", "acknowledge", "resolve"], default="trigger")
    ap.add_argument("--dry-run", action="store_true", help="print events, send nothing")
    args = ap.parse_args(argv)
    evs = sample_events(args.action)
    if args.dry_run:
        for ev in evs:
            print(json.dumps(ev))
        return 0
    key = os.environ.get("PAGERDUTY_ROUTING_KEY")
    if not key:
        ap.error("set PAGERDUTY_ROUTING_KEY to the service's integration key")
    failed = 0
    for ev in evs:
        try:
            r = events.send(ev, key)
            print(ev["event_action"], ev["dedup_key"], r.get("status") if isinstance(r, dict) else None)
        except Exception as e:  # noqa: BLE001 - every failure is counted; the rest are still sent
            failed += 1
            print(ev["event_action"], ev["dedup_key"], "FAILED", e, file=sys.stderr)
    return 1 if failed else 0
