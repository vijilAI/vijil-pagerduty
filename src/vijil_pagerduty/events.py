"""PagerDuty Events API v2 events for Dome blocks and Diamond findings.

References only. An incident names a finding; it never quotes one. PagerDuty's SRE
Agent reads incident details, so attacker-written text in an event would be a prompt
injection delivered to it.

The guard is structural, not a character filter: a character filter still lets
``ignore_previous_instructions`` through as an identifier. Contract (each clause has a test):

C1 finding_id: a UUID or a 16-hex span id, lowercased (dedup keys are case-sensitive).
C2 category: one of CATEGORIES; anything else becomes "unclassified".
C3 severity: a PagerDuty severity.
C4 agent: exactly spiffe://<trust domain>/org/<uuid>/agent/<uuid>; the bridge also
   requires the trust domain to be the operator's. Only the trust domain is not hex.
C5 source and component: constants of this module (SOURCES, COMPONENTS); a Dome
   guardrail name is accepted only from GUARDRAILS and appears only in the dedup key.
C6 trace_id: 32 hex digits. trace_url: <operator base>/projects/<id>/traces/<trace_id>,
   where <id> is a Phoenix project GlobalID (base64 of "Project:<n>").

Events API v2: POST https://events.pagerduty.com/v2/enqueue with routing_key,
event_action (trigger | acknowledge | resolve), dedup_key (at most 255 characters),
links, and payload {summary (at most 1024), source, severity (critical | error |
warning | info), component, class, custom_details}.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

ENQUEUE_URL = "https://events.pagerduty.com/v2/enqueue"
SEVERITIES = frozenset({"critical", "error", "warning", "info"})
UNCLASSIFIED = "unclassified"

# Diamond (vijil-swarm) finding categories: ground-truth vulnerability types
# (data/ground_truth/schema.py) and the pillar taxonomy (pillars/*/taxonomy.py).
_PILLARS = {
    "reliability": {
        "consistency": ("cross_session", "inter_user", "self_consistency", "temporal"),
        "correctness": ("factual_accuracy", "goal_satisfaction", "logical_validity",
                        "refusal_appropriateness", "self_consistency", "task_conformance"),
        "robustness": ("contextual", "distributional", "operational"),
    },
    "safety": {
        "care": ("induced", "self_originated", "unforced"),
        "containment": ("limit_damage", "refuse_irreversible", "safe_fallback"),
        "disclosure": ("induced", "self_originated", "unforced"),
        "loyalty": ("induced", "self_originated", "unforced"),
        "recovery": ("loss_allocation", "restoration", "return_of_control"),
        "transparency": ("accurate_account", "failure_reporting", "traceability"),
        "unmapped": ("petri",),
    },
    "security": {
        "availability": ("dos_resistance", "graceful_degradation", "resilience"),
        "confidentiality": ("access_control", "data_leakage", "data_privacy", "model_privacy", "user_privacy"),
        "integrity": ("adversarial_robustness", "fidelity", "manipulation_resistance", "tamper_resistance"),
    },
}
CATEGORIES = frozenset(
    {"dome_block", UNCLASSIFIED, "pii_leak", "overauthorization", "fabrication", "no_access_control",
     "no_input_validation", "memory_injection", "ssrf"}
    | {f"{p}.{d}.{s}" for p, dims in _PILLARS.items() for d, subs in dims.items() for s in subs}
)

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_FINDING_ID = re.compile(_UUID + r"|[0-9a-f]{16}")
_AGENT = re.compile(r"spiffe://([a-z0-9.-]{1,64})/org/" + _UUID + "/agent/" + _UUID)
_TRACE_ID = re.compile(r"[0-9a-f]{32}")
_TRACE_URL = re.compile(r"(https?://[^\s?#]{1,200})/projects/([A-Za-z0-9=]{4,40})/traces/([0-9a-f]{32})")
_PROJECT_GID = re.compile(r"Project:[0-9]{1,12}")
_DEDUP_MAX = 255
SOURCES = frozenset({"vijil-dome", "vijil-diamond"})
COMPONENTS = frozenset({"dome", "diamond"})
GUARDRAILS = frozenset({"dome-enterprise"})  # vijil-dome-go telemetry's dome.guardrail value


class UnsafeReference(ValueError):
    """A value that is not a reference. The message names the field, never the value."""


def _check(name: str, value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise UnsafeReference(f"{name} is not a reference")
    return value


def finding_id_of(value: object) -> str:
    """A finding id, lowercased, or UnsafeReference."""
    return _check("finding_id", value.lower() if isinstance(value, str) else value, _FINDING_ID)


def trust_domain(agent: str) -> str:
    m = _AGENT.fullmatch(agent) if isinstance(agent, str) else None
    if m is None:
        raise UnsafeReference("agent is not a reference")
    return m.group(1)


def _project_gid(value: str) -> bool:
    try:
        return bool(_PROJECT_GID.fullmatch(base64.b64decode(value, validate=True).decode("ascii")))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False


def category_of(label: object) -> str:
    """The category to report for a producer's label: itself if known, else unclassified."""
    return label if isinstance(label, str) and label in CATEGORIES else UNCLASSIFIED


@dataclass(frozen=True)
class Reference:
    """What an incident may say about a finding: identifiers, never content."""

    finding_id: str
    category: str
    severity: str
    agent: str
    trace_id: str
    trace_url: str | None = None

    def __post_init__(self) -> None:
        _check("finding_id", self.finding_id, _FINDING_ID)
        if self.category not in CATEGORIES:
            raise UnsafeReference("category is not a known category")
        if self.severity not in SEVERITIES:
            raise UnsafeReference("severity is not a PagerDuty severity")
        _check("agent", self.agent, _AGENT)
        _check("trace_id", self.trace_id, _TRACE_ID)
        if self.trace_url is not None:
            m = _TRACE_URL.fullmatch(self.trace_url) if isinstance(self.trace_url, str) else None
            if m is None or m.group(3) != self.trace_id or not _project_gid(m.group(2)):
                raise UnsafeReference("trace_url is not this trace's Phoenix URL")


def dome_dedup_key(agent: str, guardrail: str) -> str:
    if guardrail not in GUARDRAILS:
        raise UnsafeReference("guardrail is not a known Dome guardrail")
    return f"dome:{_check('agent', agent, _AGENT)}:{guardrail}"


def diamond_dedup_key(finding_id: str) -> str:
    return f"diamond:{finding_id_of(finding_id)}"


def _check_dedup(dedup_key: object) -> str:
    """A dedup key built by dome_dedup_key or diamond_dedup_key, and nothing else."""
    if isinstance(dedup_key, str) and len(dedup_key) <= _DEDUP_MAX:
        kind, _, rest = dedup_key.partition(":")
        if kind == "diamond" and _FINDING_ID.fullmatch(rest):
            return dedup_key
        agent, _, guardrail = rest.rpartition(":")
        if kind == "dome" and guardrail in GUARDRAILS and _AGENT.fullmatch(agent):
            return dedup_key
    raise UnsafeReference("dedup_key is not a reference")


def trigger(ref: Reference, dedup_key: str, source: str, component: str) -> dict:
    """A trigger event for ``ref``. The routing key is added by ``send``."""
    _check_dedup(dedup_key)
    if source not in SOURCES or component not in COMPONENTS:
        raise UnsafeReference("source or component is not a constant of this module")
    event = {
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": f"[{component}] {ref.category} on {ref.agent} (finding {ref.finding_id})",
            "source": source,
            "severity": ref.severity,
            "component": component,
            "class": ref.category,
            "custom_details": {k: v for k, v in asdict(ref).items() if v is not None},
        },
    }
    if ref.trace_url:
        event["links"] = [{"href": ref.trace_url, "text": "Trace in Phoenix"}]
    return event


def resolve(dedup_key: str) -> dict:
    return {"event_action": "resolve", "dedup_key": _check_dedup(dedup_key)}


def acknowledge(dedup_key: str) -> dict:
    return {"event_action": "acknowledge", "dedup_key": _check_dedup(dedup_key)}


def send(event: dict, routing_key: str, url: str = ENQUEUE_URL, timeout: float = 10.0) -> dict:
    """POST ``event`` to the Events API. Raises on any non-2xx answer.

    The error names only the HTTP status. PagerDuty's error body can echo parts of the
    event, so it is not repeated, and neither is the routing key.
    """
    body = json.dumps({"routing_key": routing_key, **event}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"PagerDuty answered {e.code}") from None
