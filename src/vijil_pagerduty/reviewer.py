"""Send sample Vijil events to a PagerDuty integration, with no Vijil account.

    vijil-pagerduty test [--action trigger|acknowledge|resolve] [--dry-run]

Environment: PAGERDUTY_INTEGRATION_KEY, the Integration Key of the service under test.

The samples have the same shape as the events Vijil Console sends (tests/console_events.json
pins them to Console's output). trigger sends one Dome block event twice (same dedup key:
PagerDuty keeps one alert) and one Diamond red team event. acknowledge and resolve act on both.
The Dome sample's agent is in the trust domain test.vijil.ai; the red team sample names the same
agent by its all-zero test ID.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from vijil_pagerduty import events

ORG = "00000000-0000-4000-8000-000000000001"
AGENT_ID = "00000000-0000-4000-8000-000000000002"
AGENT = f"spiffe://test.vijil.ai/org/{ORG}/agent/{AGENT_ID}"
CONTROL = "prompt_injection"
EVALUATION_ID = "00000000-0000-4000-8000-0000000000e1"
WINDOW_SECONDS = 900
DOME_KEY = f"dome:{AGENT}:{CONTROL}"
DIAMOND_KEY = f"redteam:{EVALUATION_ID}"


def dome_block(now: int) -> dict:
    return {
        "event_action": "trigger",
        "dedup_key": DOME_KEY,
        "payload": {
            "summary": f"Vijil Dome blocked 2 request(s) at {CONTROL} from agent {AGENT} in {WINDOW_SECONDS // 60} min",
            "source": "vijil-dome",
            "severity": "error",
            "component": "dome",
            "class": "dome_block",
            "custom_details": {
                "agent": AGENT,
                "control": CONTROL,
                "blocked_count": 2,
                "first_blocked_at": now - 60,
                "last_blocked_at": now,
                "window_seconds": WINDOW_SECONDS,
                "window_truncated": False,
                "trace_id": "0000000000000000000000000000d0e1",
            },
        },
    }


def diamond_red_team() -> dict:
    return {
        "event_action": "trigger",
        "dedup_key": DIAMOND_KEY,
        "payload": {
            "summary": f"Vijil Diamond red team on agent {AGENT_ID}: vulnerabilities: 2, policy violations: 0, leaked artifacts: 1",
            "source": "vijil-diamond",
            "severity": "warning",
            "component": "diamond",
            "class": "redteam",
            "custom_details": {
                "evaluation_id": EVALUATION_ID,
                "agent_id": AGENT_ID,
                "vulnerabilities": 2,
                "policy_violations": 0,
                "leaked_artifacts": 1,
            },
        },
    }


def sample_events(action: str, now: int) -> list[dict]:
    if action == "trigger":
        dome = dome_block(now)
        return [dome, dome, diamond_red_team()]
    build = events.acknowledge if action == "acknowledge" else events.resolve
    return [build(DOME_KEY), build(DIAMOND_KEY)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vijil-pagerduty test", description=__doc__.split("\n")[0])
    ap.add_argument("--action", choices=["trigger", "acknowledge", "resolve"], default="trigger")
    ap.add_argument("--dry-run", action="store_true", help="print events, send nothing")
    args = ap.parse_args(argv)
    evs = sample_events(args.action, int(time.time()))
    if args.dry_run:
        for ev in evs:
            print(json.dumps(ev))
        return 0
    key = os.environ.get("PAGERDUTY_INTEGRATION_KEY")
    if not key:
        ap.error("set PAGERDUTY_INTEGRATION_KEY to the service's Integration Key")
    failed = 0
    for ev in evs:
        try:
            r = events.send(ev, key)
            print(ev["event_action"], ev["dedup_key"], r.get("status") if isinstance(r, dict) else None)
        except Exception as e:  # noqa: BLE001 - every failure is counted; the rest are still sent
            failed += 1
            print(ev["event_action"], ev["dedup_key"], "FAILED", e, file=sys.stderr)
    return 1 if failed else 0
