# vijil-pagerduty

Vijil Console sends Dome blocks and Diamond findings to PagerDuty as incidents, through the PagerDuty Events API v2. This package does not send them; Console does. It holds the integration guide and a `test` command that sends sample events, so you can check a PagerDuty Integration Key without a Vijil account.

Setup for customers: [docs/integration-guide.md](docs/integration-guide.md).

## Test the integration without a Vijil account

This section is for PagerDuty's app reviewers and for anyone checking a new Integration Key. It needs Python 3.11 or later and nothing else.

1. In PagerDuty, add the **Vijil** integration to a test service that pages no one, and copy its **Integration Key**. An **Events API V2** integration's Integration Key works the same way. For the low- and high-urgency split below, set the service's **Urgency** to follow alert severity.
2. Install the package and trigger the sample incidents:
   ```
   pip install vijil-pagerduty
   export PAGERDUTY_INTEGRATION_KEY=<Integration Key>
   vijil-pagerduty test
   ```
   Until the package is on PyPI, install it from this repository instead: `pip install git+https://github.com/vijilAI/vijil-pagerduty`.

   The command sends one Dome block event twice and one Diamond red team event, built exactly as Vijil Console builds real ones. The service shows two incidents:
   * A Dome block at severity `error` (high urgency), with one alert, because both Dome events share a deduplication key.
   * A Diamond red team result at severity `warning` (low urgency), counting 2 vulnerabilities and 1 leaked artifact.

   Both samples name one test agent: the Dome event by its SPIFFE ID in the trust domain `test.vijil.ai`, the red team event by its test ID. They look like real events on purpose. Console's own `vijil-console pagerduty test` instead sends events titled `[Test]`.
3. Acknowledge, then resolve, both incidents:
   ```
   vijil-pagerduty test --action acknowledge
   vijil-pagerduty test --action resolve
   ```

Each command prints one line per event with PagerDuty's answer, and exits with status 1 if any send failed. Add `--dry-run` to print the events without sending them. PagerDuty answers `success` for any well-formed key, even one it does not recognize, and drops those events; if no incidents appear, check the key.

## Develop

```
uv sync
uv run pytest
uv run ruff check
```

`tests/console_events.json` is the output of Console's own event builders for the sample inputs, so a test fails if the samples drift from what Console sends. Regenerate it from vijil-console when Console's event format changes.
