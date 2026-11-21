<!-- DRAFT for the PagerDuty Distribution Form, written from PagerDuty's template
(github.com/PagerDuty/app-documentation-templates, integration-guide-template.md).
Every behavior below is what pagerduty/bridge.py and pagerduty/events.py do today.
Open before submission (delete this block when done):
  1. Support contact: a Vijil support address (the template forbids PagerDuty's).
  2. Install step: assumes vijil-pagerduty is published on PyPI.
  3. Urgency label: confirm the exact name of the service urgency setting in the PagerDuty UI.
  4. Integration Type name: "Vijil" assumes the app is registered under that name.
  5. PagerDuty UI labels (Service Directory, Add an integration): check against the live UI.
-->

# PagerDuty + Vijil Integration Benefits

* Page on-call responders when Dome Enterprise blocks an AI agent's tool call, so an attack on a live agent reaches the people who handle production incidents.
* Open a low-urgency incident for each severe Diamond finding, so a vulnerability found in testing gets an owner without waking anyone.
* Group a burst of Dome blocks on one agent into one incident, and resolve it automatically when the blocks stop.
* Link every incident to the exact trace in your Arize Phoenix instance, where the responder sees the attack, the agent's steps, and the blocked tool call.
* Keep attacker-written text out of PagerDuty. Incidents carry identifiers only, so they are safe for PagerDuty's SRE Agent and other automation to read.

# How it Works

* Vijil's runtime controls (Dome Enterprise) and evaluation engine (Diamond) write their results to your Phoenix instance. The Vijil bridge reads those results from Phoenix and sends events to PagerDuty through the Events API v2.
* **Dome blocks:** the bridge groups blocks by agent. When an agent has at least one block (configurable) in the last 15 minutes (configurable), the bridge sends a trigger event at severity `error`. Further blocks on the same agent join the open incident, because they share one deduplication key. When a run finds no new blocks on that agent in the window, the bridge sends a resolve event and the incident resolves.
* **Diamond findings:** each finding with a severity of 10 on Diamond's 0 to 10 scale (configurable) triggers an incident at severity `warning`. A rerun of the same evaluation updates the existing incident instead of opening a new one. Diamond incidents do not resolve automatically; resolve them in PagerDuty once the agent or its policy is fixed.
* Every incident contains: a finding ID, a category from a fixed list, the agent's SPIFFE identity, a severity, the trace ID, and a **Trace in Phoenix** link. A category outside the list is sent as `unclassified`. A record that cannot be reduced to these fields is skipped and counted, never sent.

# Requirements

* A PagerDuty account role that can add integrations to a service. If you do not have one, ask an Admin or Account Owner in your organization to configure the integration.
* A self-hosted Arize Phoenix instance that receives your agent's traces. Vijil has tested this integration with Phoenix 21.1.0.
* A Phoenix API key that can read the project your agent writes to.
* Vijil Dome Enterprise in front of your agent's tools (for Dome block incidents), a Vijil Diamond evaluation of your agent (for Diamond finding incidents), or both.
* Agents identified by SPIFFE IDs of the form `spiffe://<trust domain>/org/<uuid>/agent/<uuid>`.
* Python 3.11 or later on the host that runs the bridge, and a scheduler such as cron.

# Support

If you need help with this integration, please contact Vijil at **[VIJIL-SUPPORT-CONTACT]**.

# Integration Walkthrough

## In PagerDuty

### Integrating With a PagerDuty Service

1. From the **Services** menu, select **Service Directory**.
2. There are two ways to add an integration to a service:
   * **If you are adding your integration to an existing service**: Click the **name** of the service you want to add the integration to. Then, select the **Integrations** tab and click **Add an integration**.
   * **If you are creating a new service for your integration**: Follow the steps in PagerDuty's [Create a New Service](https://support.pagerduty.com/docs/services-and-integrations#section-create-a-new-service) documentation, selecting **Vijil** as the **Integration Type**. Then continue with step 5.
3. Enter an **Integration Name** in the format `vijil-service-name` (for example, `Vijil-Travel-Agent`) and select **Vijil** from the **Integration Type** menu.
4. Click the **Add Integration** button to save your new integration. PagerDuty returns you to the **Integrations** tab for your service.
5. Copy the **Integration Key** from this screen and keep it in a safe place. You will use it to configure the Vijil bridge in the next section.
6. To page Diamond findings at low urgency, open the service's **Settings** tab and set the service's **Urgency** to follow alert severity. With this setting, Dome blocks (severity `error`) page at high urgency and Diamond findings (severity `warning`) at low urgency.

## In Vijil

1. **Install the bridge** on a host that can reach both your Phoenix instance and `events.pagerduty.com`:
   ```
   pip install vijil-pagerduty
   ```
2. **Set four environment variables** on that host:
   * `PAGERDUTY_ROUTING_KEY`: the **Integration Key** you copied from PagerDuty.
   * `PHOENIX_URL`: the base URL of your Phoenix instance, for example `https://phoenix.example.com`. Do not include a username or password in the URL; the bridge refuses one, because the URL appears in incident links.
   * `PHOENIX_API_KEY`: your Phoenix API key.
   * `SPIFFE_TRUST_DOMAIN` (optional): the SPIFFE trust domain of your agents. The default is `vijil.ai`, the trust domain of agents registered in Vijil. The bridge never names an agent from another trust domain in an incident.
3. **Check the configuration without sending anything.** Run the following command, replacing `<project>` with your Phoenix project name. The bridge prints the events it would send, and sends none:
   ```
   vijil-pagerduty dome --project <project> --dry-run
   ```
4. **Schedule Dome block events.** Add a cron entry that runs the bridge every 5 minutes:
   ```
   */5 * * * * vijil-pagerduty dome --project <project>
   ```
   Optional settings: `--window-min` (default 15) sets how long an agent must go without a block before its incident resolves, and `--threshold` (default 1) sets how many blocks in that window open an incident.
5. **Send Diamond findings after each evaluation.** Run the following command, replacing `<agent>` with the SPIFFE ID of the agent Diamond tested:
   ```
   vijil-pagerduty diamond --project <project> --agent <agent>
   ```
   Run it within 24 hours of the evaluation, or raise `--lookback-min` (default 1440 minutes), because the bridge looks for findings only on recent traces. Optional setting: `--min-severity` (default 10) sets the lowest Diamond severity that opens an incident.
6. **Read the bridge's summary.** Each run prints how many records it read, how many events it sent, how many records it skipped, and how many sends failed. The bridge exits with status 1 if it skipped or failed to send anything, so your scheduler can alert on it.

To confirm the integration, run step 5 after a Diamond evaluation that produced a severity-10 finding. A low-urgency incident appears on your PagerDuty service. Click **Trace in Phoenix** in the incident to open the finding's trace.

# How to Uninstall

1. In PagerDuty, open your service, select the **Integrations** tab, and delete the **Vijil** integration. PagerDuty stops accepting events sent with its Integration Key.
2. On the bridge host, remove the cron entries for the bridge and delete the `PAGERDUTY_ROUTING_KEY` environment variable.
3. Resolve any open Vijil incidents in PagerDuty. The bridge resolves Dome incidents only while it runs, and never resolves Diamond incidents.
