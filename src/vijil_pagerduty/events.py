"""Sends events to the PagerDuty Events API v2.

The routing key is added here and never printed. An error names only PagerDuty's HTTP status:
its error body can echo parts of the event, so it is not repeated.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

ENQUEUE_URL = "https://events.pagerduty.com/v2/enqueue"


def acknowledge(dedup_key: str) -> dict:
    return {"event_action": "acknowledge", "dedup_key": dedup_key}


def resolve(dedup_key: str) -> dict:
    return {"event_action": "resolve", "dedup_key": dedup_key}


def send(event: dict, routing_key: str, url: str = ENQUEUE_URL, timeout: float = 10.0) -> dict:
    """POST ``event`` to the Events API. Raises on any non-2xx answer or an unreachable endpoint."""
    body = json.dumps({"routing_key": routing_key, **event}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"PagerDuty answered {e.code}") from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"PagerDuty unreachable ({type(e).__name__})") from None
