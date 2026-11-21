# vijil-pagerduty

Sends Vijil Dome Enterprise blocks and Diamond findings to PagerDuty as incidents, through the PagerDuty Events API v2. It reads the results from your Arize Phoenix instance. Incidents carry identifiers only, never attacker-written text.

Setup for customers: [docs/integration-guide.md](docs/integration-guide.md).

## Test the integration without Phoenix or a Vijil account

This section is for PagerDuty's app reviewers and for anyone checking a new integration key. It needs Python 3.11 or later and nothing else.

1. In PagerDuty, add the **Vijil** integration to a test service and copy its **Integration Key**.
2. Install the package and trigger the sample incidents:
   ```
   pip install vijil-pagerduty
   export PAGERDUTY_ROUTING_KEY=<integration key>
   vijil-pagerduty test
   ```
   The command sends one Dome block event twice and one Diamond finding event. The service shows two incidents: a Dome block at severity `error`, with both events grouped into it, and a Diamond `pii_leak` finding at severity `warning`. Every sample incident names the agent's trust domain as `test.vijil.ai`.
3. Acknowledge, then resolve, both incidents:
   ```
   vijil-pagerduty test --action acknowledge
   vijil-pagerduty test --action resolve
   ```

Each command prints one line per event with PagerDuty's answer, and exits with status 1 if any send failed. Add `--dry-run` to print the events without sending them.

## Use

```
vijil-pagerduty dome    --project P [--window-min 15] [--threshold 1] [--dry-run]
vijil-pagerduty diamond --project P --agent spiffe://... [--min-severity 10] [--dry-run]
vijil-pagerduty test    [--action trigger|acknowledge|resolve] [--dry-run]
```

Environment: `PAGERDUTY_ROUTING_KEY`, `PHOENIX_URL`, `PHOENIX_API_KEY`, and optionally `SPIFFE_TRUST_DOMAIN` (default `vijil.ai`).

## Develop

```
uv sync
uv run pytest
uv run ruff check
```
