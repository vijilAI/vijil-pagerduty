import json

import pytest

from vijil_pagerduty import events, reviewer


def test_trigger_sends_one_dome_incident_twice_and_one_diamond():
    evs = reviewer.sample_events("trigger")
    assert [e["dedup_key"] for e in evs] == [reviewer.DOME_KEY, reviewer.DOME_KEY, reviewer.DIAMOND_KEY]
    assert [e["payload"]["severity"] for e in evs] == ["error", "error", "warning"]
    assert all("test.vijil.ai" in e["payload"]["summary"] for e in evs)


@pytest.mark.parametrize("action", ["acknowledge", "resolve"])
def test_follow_up_actions_target_both_incidents(action):
    evs = reviewer.sample_events(action)
    assert evs == [{"event_action": action, "dedup_key": k} for k in (reviewer.DOME_KEY, reviewer.DIAMOND_KEY)]


def test_dry_run_sends_nothing(monkeypatch, capsys):
    monkeypatch.setattr(events, "send", lambda *a, **k: pytest.fail("dry run sent an event"))
    assert reviewer.main(["--dry-run"]) == 0
    assert len([json.loads(line) for line in capsys.readouterr().out.splitlines()]) == 3


def test_missing_key_is_an_error_not_a_silent_success(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    with pytest.raises(SystemExit) as e:
        reviewer.main([])
    assert e.value.code == 2


def test_a_failed_send_exits_1_and_the_rest_are_still_sent(monkeypatch):
    sent = []

    def send(ev, key):
        sent.append(ev)
        if len(sent) == 1:
            raise RuntimeError("PagerDuty answered 400")
        return {"status": "success"}

    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "k")
    monkeypatch.setattr(events, "send", send)
    assert reviewer.main([]) == 1
    assert len(sent) == 3
