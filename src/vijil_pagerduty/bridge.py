"""Turn Dome Enterprise blocks and Diamond findings in Phoenix into PagerDuty events.

    vijil-pagerduty dome    --project P [--window-min 15] [--threshold 1] [--dry-run]
    vijil-pagerduty diamond --project P --agent spiffe://... [--min-severity 10] [--dry-run]

Environment: PHOENIX_URL (default http://localhost:6006; a path prefix is allowed),
PHOENIX_API_KEY, PAGERDUTY_ROUTING_KEY, and SPIFFE_TRUST_DOMAIN (default vijil.ai):
an agent outside the operator's trust domain is never named in an incident.

Only identifiers are read from Phoenix: span names, ids, timestamps, and the outcome
attributes of decision spans; for findings, the annotation's label, score, finding_id,
and trace id. A finding's explanation can quote the attack, so it is never read.

dome: blocks in the window, grouped by agent and guardrail. A group at or over the
threshold triggers one incident (dedup_key dome:<agent>:<guardrail>, so a burst is
one incident). A group seen in the lookback with no block in the window is resolved;
a group with blocks in the window but under the threshold is left as it is.

diamond: each finding at or over --min-severity (0-10 scale, default 10: page only on
the most severe findings) triggers an incident at severity "warning", which a service
whose urgency follows alert severity treats as low urgency. dedup_key is
diamond:<finding_id>, so a rerun updates it instead of duplicating it. Repeated
annotations of one finding become one event.
Findings are looked up on the traces seen within --lookback-min.

B1 Any record that cannot be turned into references, or is malformed in any way, is
   skipped and counted, never sent; the rest are still sent.
B2 Every list endpoint is read to its last page; a repeated cursor or more than
   MAX_PAGES pages is an error, not a silent stop.
B3 Counts go to stderr on every path, and the exit status is 1 when anything was
   skipped, failed to send, or --only matched nothing.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from vijil_pagerduty import events

DECISION_SPAN = "dome.enterprise.tool_call"
FINDING_ANNOTATION = "vijil.finding"
PAGE = 1000
MAX_PAGES = 1000
MAX_MINUTES = 366 * 24 * 60
MALFORMED = (KeyError, TypeError, ValueError, AttributeError)


def _base() -> str:
    base = os.environ.get("PHOENIX_URL", "http://localhost:6006").rstrip("/")
    if "@" in urllib.parse.urlsplit(base).netloc:
        raise SystemExit("PHOENIX_URL must not carry credentials; they would appear in incident links")
    return base


def _phoenix(path: str) -> dict:
    req = urllib.request.Request(_base() + path, headers={"Authorization": "Bearer " + os.environ["PHOENIX_API_KEY"]})
    with urllib.request.urlopen(req, timeout=30) as f:
        return json.loads(f.read())


def _pages(path: str, query: list[tuple[str, str]]) -> list[dict]:
    """Every page of a Phoenix list endpoint (they default to small pages)."""
    out: list[dict] = []
    cursor, seen = None, set()
    for _ in range(MAX_PAGES):
        q = query + [("limit", str(PAGE))] + ([("cursor", cursor)] if cursor else [])
        page = _phoenix(path + "?" + urllib.parse.urlencode(q))
        out += list(page.get("data") or [])
        cursor = page.get("next_cursor")
        if not cursor:
            return out
        if cursor in seen:
            raise RuntimeError("Phoenix pagination did not advance")
        seen.add(cursor)
    raise RuntimeError(f"Phoenix pagination exceeded {MAX_PAGES} pages")


def _project_path(project: str) -> str:
    return "/v1/projects/" + urllib.parse.quote(project, safe="")


def _spans(project: str, since: datetime) -> list[dict]:
    return _pages(_project_path(project) + "/spans", [("start_time", since.isoformat())])


def _finding_annotations(project: str, trace_ids: list[str]) -> list[dict]:
    out = []
    for i in range(0, len(trace_ids), 50):
        q = [("trace_ids", t) for t in trace_ids[i : i + 50]] + [("include_annotation_names", FINDING_ANNOTATION)]
        out += _pages(_project_path(project) + "/trace_annotations", q)
    return out


def _trace_url_for(project: str):
    ids = [p.get("id") for p in _pages("/v1/projects", []) if isinstance(p, dict) and p.get("name") == project]
    if not ids:
        raise SystemExit(f"project {project!r} not found in Phoenix")
    base = _base()
    return lambda trace_id: f"{base}/projects/{ids[0]}/traces/{trace_id}"


def _ts(span: dict) -> datetime:
    t = datetime.fromisoformat(span["start_time"])
    if t.tzinfo is None:
        raise ValueError("naive timestamp")
    return t


def dome_events(spans: list[dict], window_start: datetime, threshold: int, trace_url, skipped: Counter,
                trust_domain: str = "vijil.ai") -> list[dict]:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    blocks: dict[tuple[str, str], list[tuple[datetime, str, str]]] = defaultdict(list)
    for s in spans:
        try:
            if not isinstance(s, dict):
                raise TypeError("record is not a mapping")
            if s.get("name") != DECISION_SPAN:
                continue
            a = s["attributes"]
            if not isinstance(a, dict):
                raise TypeError("attributes is not a mapping")
            if a.get("dome.decision") != "blocked":
                continue
            agent, guardrail = a.get("agent.id"), a.get("dome.guardrail")
            ctx = s["context"]
            entry = (_ts(s), ctx["trace_id"], ctx["span_id"])
            if not all(isinstance(v, str) for v in (agent, guardrail, entry[1], entry[2])):
                raise TypeError("an identifier is not a string")
            blocks[(agent, guardrail)].append(entry)
        except MALFORMED:
            skipped["malformed record"] += 1
    out = []
    for (agent, guardrail), group in blocks.items():
        try:
            if events.trust_domain(agent) != trust_domain:
                raise events.UnsafeReference("agent is outside the trust domain")
            dedup = events.dome_dedup_key(agent, guardrail)
            recent = [g for g in group if g[0] >= window_start]
            if recent and len(recent) >= threshold:
                _, trace_id, span_id = max(recent)
                ref = events.Reference(
                    finding_id=events.finding_id_of(span_id), category="dome_block", severity="error",
                    agent=agent, trace_id=trace_id, trace_url=trace_url(trace_id),
                )
                out.append(events.trigger(ref, dedup, source="vijil-dome", component="dome"))
            elif not recent:
                out.append(events.resolve(dedup))
        except events.UnsafeReference as e:
            skipped[str(e)] += len(group)
    return sorted(out, key=lambda e: e["dedup_key"])


# Diamond findings are test results, not live operations: they page at low urgency. PagerDuty
# maps warning and info to low urgency when the service's urgency follows alert severity.
DIAMOND_SEVERITY = "warning"


def diamond_events(annotations: list[dict], agent: str, min_severity: float, trace_url, skipped: Counter,
                   trust_domain: str = "vijil.ai") -> list[dict]:
    if events.trust_domain(agent) != trust_domain:
        raise events.UnsafeReference("agent is outside the trust domain")
    best: dict[str, tuple[float, dict]] = {}
    for a in annotations:
        try:
            if not isinstance(a, dict):
                raise TypeError("record is not a mapping")
            if a.get("name") != FINDING_ANNOTATION:
                continue
            result, meta = a["result"], a["metadata"]
            score = result.get("score")
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
                skipped["score is not a number"] += 1
                continue
            if score < min_severity:
                continue
            finding_id, trace_id = events.finding_id_of(meta.get("finding_id")), a.get("trace_id")
            ref = events.Reference(
                finding_id=finding_id, category=events.category_of(result.get("label")), severity=DIAMOND_SEVERITY,
                agent=agent, trace_id=trace_id, trace_url=trace_url(trace_id),
            )
            ev = events.trigger(ref, events.diamond_dedup_key(finding_id), source="vijil-diamond", component="diamond")
            if finding_id not in best or score > best[finding_id][0]:
                best[finding_id] = (score, ev)
        except events.UnsafeReference as e:
            skipped[str(e)] += 1
        except MALFORMED:
            skipped["malformed record"] += 1
    return [ev for _, ev in best.values()]


def _trace_ids(spans: list[dict]) -> list[str]:
    out = set()
    for s in spans:
        ctx = s.get("context") if isinstance(s, dict) else None
        t = ctx.get("trace_id") if isinstance(ctx, dict) else None
        if isinstance(t, str):
            out.add(t)
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vijil-pagerduty")
    ap.add_argument("kind", choices=["dome", "diamond"])
    ap.add_argument("--project", required=True)
    ap.add_argument("--window-min", type=float, default=15)
    ap.add_argument("--lookback-min", type=float, default=24 * 60)
    ap.add_argument("--threshold", type=int, default=1)
    ap.add_argument("--min-severity", type=float, default=10)
    ap.add_argument("--agent", help="SPIFFE id of the agent Diamond tested (diamond only)")
    ap.add_argument("--only", action="append", default=[],
                    help="send only events whose finding_id or dedup_key is given")
    ap.add_argument("--dry-run", action="store_true", help="print events, send nothing")
    args = ap.parse_args(argv)
    if args.threshold < 1:
        ap.error("--threshold must be at least 1")
    if not all(math.isfinite(x) for x in (args.window_min, args.lookback_min, args.min_severity)):
        ap.error("--window-min, --lookback-min and --min-severity must be finite")
    if not (0 < args.window_min <= MAX_MINUTES and 0 < args.lookback_min <= MAX_MINUTES):
        ap.error(f"--window-min and --lookback-min must be in (0, {MAX_MINUTES}]")
    domain = os.environ.get("SPIFFE_TRUST_DOMAIN", "vijil.ai")
    if args.kind == "diamond":
        if not args.agent:
            ap.error("diamond needs --agent")
        try:
            if events.trust_domain(args.agent) != domain:
                ap.error("--agent is outside SPIFFE_TRUST_DOMAIN")
        except events.UnsafeReference:
            ap.error("--agent is not spiffe://<trust domain>/org/<uuid>/agent/<uuid>")

    now = datetime.now(UTC)
    spans = _spans(args.project, now - timedelta(minutes=max(args.lookback_min, args.window_min)))
    trace_url = _trace_url_for(args.project)
    skipped: Counter = Counter()
    if args.kind == "dome":
        evs = dome_events(spans, now - timedelta(minutes=args.window_min), args.threshold, trace_url, skipped, domain)
        read = sum(1 for s in spans if s.get("name") == DECISION_SPAN)
    else:
        annotations = _finding_annotations(args.project, _trace_ids(spans))
        evs = diamond_events(annotations, args.agent, args.min_severity, trace_url, skipped, domain)
        read = len(annotations)

    unmatched = False
    if args.only:
        wanted = set(args.only)
        evs = [e for e in evs if e["dedup_key"] in wanted
               or e.get("payload", {}).get("custom_details", {}).get("finding_id") in wanted]
        unmatched = not evs

    failed = 0
    key = None if args.dry_run else os.environ["PAGERDUTY_ROUTING_KEY"]
    for ev in evs:
        if key is None:
            print(json.dumps(ev))
            continue
        try:
            r = events.send(ev, key)
            status = r.get("status") if isinstance(r, dict) else None
            print(ev["event_action"], ev["dedup_key"], status, file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - B3: any send failure is counted and the rest are still sent
            failed += 1
            print(ev["event_action"], ev["dedup_key"], "FAILED", type(e).__name__, file=sys.stderr)
    print(f"read {read}, events {len(evs)}, skipped {sum(skipped.values())} {dict(skipped)}, failed {failed}"
          + (", --only matched no event" if unmatched else ""), file=sys.stderr)
    return 1 if skipped or failed or unmatched else 0


if __name__ == "__main__":
    sys.exit(main())
