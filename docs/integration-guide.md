<!-- DRAFT for the PagerDuty Distribution Form, written from PagerDuty's template
(github.com/PagerDuty/app-documentation-templates, integration-guide-template.md).
Every behavior below is what Vijil Console does (vijil-console CON-816, PRs #1627, #1628, #1630;
Diamond red team alerts CON-820). Console also pages Swarm exploration findings; this guide leaves
them out until the swarm runs in production (it will be named Diamond or Red Swarm).
Open before submission (delete this block when done):
  1. The `vijil-console pagerduty` commands ship in the first CLI release after #1630 merges;
     0.4.23, the current release, does not have them. State the minimum version once known.
  2. Hosted Console: PagerDuty alerts must be turned on for Vijil's hosted deployments.
  3. Run every "In Vijil" command against a deployed Console, through its gateway. So far they
     have run in process only; the gateway route they need is in #1630.
  4. Confirm on console.vijil.ai that a completed red team run pages, which also confirms
     Agent Environment can read the red team workflows and reports.
  5. Integration Type name: "Vijil" assumes the app is registered under that name.
  6. PagerDuty UI labels (Service Directory, Add an integration, the urgency setting): check
     against the live UI. Verified 2026-11-22 against a live service: an urgency rule of
     severity_based paged Dome events at high urgency and Diamond findings at low; a 32-character
     key PagerDuty does not know is accepted (202) and dropped; any other key gets 400.
-->

# PagerDuty + Vijil Integration Benefits

This guide is for the PagerDuty administrator who connects a PagerDuty service to Vijil. Any member of your team in Vijil Console can do the steps in Vijil.

* Page on-call responders when Vijil Dome blocks attacks on an AI agent, so an attack on a live agent gets the attention of the people who handle production incidents.
* Get one incident per agent and control, not one per blocked action. Repeat blocks join the open incident, so a burst of attacks does not flood your on-call.
* Keep attacker-written text out of PagerDuty. Incidents carry identifiers and counts only, so they are safe for PagerDuty's agents to read.
* Open a low-urgency incident for each Vijil Diamond red team run that finds a weakness, so a vulnerability found in testing gets an owner without waking anyone.

# How it Works

* Vijil Console sends events to your PagerDuty service through the Events API v2. You store the service's Integration Key in Console once; nothing else runs on your side.
* **Dome enforces policy:** Dome is Vijil's runtime protection for agents. About once a minute, Console reads the actions Dome blocked for your team in the last 15 minutes. It groups them by agent and by the control that blocked them, such as `prompt_injection`. Each group sends a trigger event at severity `error`, with the deduplication key `dome:<agent>:<control>`, so further blocks of the same kind join the open incident. Console pages again only for a newly blocked action, including after you resolve the incident. The one exception is a Console restart, which can page the last 15 minutes of blocks once more.
* **Diamond finds faults:** Diamond is Vijil's adversarial testing of agents. When a Diamond red team run completes and its report lists at least one vulnerability, policy violation, or leaked artifact, Console sends one trigger event at severity `warning`, with the deduplication key `redteam:<evaluation ID>`. Each run is reported once.
* Console never resolves an incident. Resolve Dome incidents once the attack stops, and Diamond incidents once the agent or its policy is fixed.
* Events carry identifiers and counts, never request or response text, so text an attacker wrote never reaches PagerDuty. They include:
  * Dome: the agent's ID, the control's name, the number of blocked actions, the first and last block times, and a trace ID.
  * Diamond: the evaluation and agent IDs, and the number of vulnerabilities, policy violations, and leaked artifacts the report lists.
* An agent appears by its Vijil Console ID or SPIFFE ID. Blocks on an agent Vijil cannot identify share one incident, under the agent name `unattributed`.

# Requirements

* A PagerDuty account role that can add integrations to a service. If you do not have one, ask an Admin or Account Owner in your organization to configure the integration.
* A Vijil Console team whose agents are protected by Dome, with Dome reporting to Console, or tested with Diamond red team runs, or both.
* PagerDuty alerts turned on for your Vijil Console. On Console hosted by Vijil, ask Vijil support. On a Console your organization runs, ask the people who run it.
* The Vijil Console command-line tool, logged in, with your team selected. On a Console your organization runs, first point the tool at it with `vijil-console auth init --url <your Console URL>`.
  ```
  pip install vijil-console
  vijil-console auth login
  vijil-console team list
  vijil-console team use <team ID>
  ```
  If your organization signs in to Vijil through single sign-on, use `vijil-console auth login-browser` instead of `auth login`.

# Support

If you need help with this integration, please contact Vijil at **support@vijil.ai**.

# Integration Walkthrough

## In PagerDuty

### Integrating With a PagerDuty Service

1. From the **Services** menu, select **Service Directory**.
2. There are two ways to add an integration to a service:
   * **If you are adding your integration to an existing service**: Click the **name** of the service you want to add the integration to. Then, select the **Integrations** tab and click **Add an integration**.
   * **If you are creating a new service for your integration**: Follow the steps in PagerDuty's [Create a New Service](https://support.pagerduty.com/docs/services-and-integrations#section-create-a-new-service) documentation, selecting **Vijil** as the **Integration Type**. Then continue with step 5.
3. Enter an **Integration Name** in the format `Vijil-service-name` (for example, `Vijil-Travel-Agent`) and select **Vijil** from the **Integration Type** menu.
4. Click the **Add Integration** button to save your new integration. PagerDuty returns you to the **Integrations** tab for your service.
5. Copy the **Integration Key** from this screen and keep it in a safe place. You will store it in Vijil Console in the next section.
6. Open the service's **Settings** tab and set the service's **Urgency** to follow alert severity. Dome blocks (severity `error`) then page at high urgency and Diamond red team results (severity `warning`) at low urgency. Without this setting, the service's own urgency applies to both.

### Routing with Event Orchestration (optional)

Each event's `component` field is `dome` or `diamond`. Its `class` field is `dome_block` for Dome blocks and `redteam` for Diamond red team runs. Use these fields in an Event Orchestration rule to send Dome blocks and Diamond red team results to different services or escalation policies.

## In Vijil

**Step 1. Store the Integration Key.** Run the following command, then paste the **Integration Key** at the `Integration key:` prompt. The key does not appear on screen, and no command can read it back.

```
vijil-console pagerduty set
```

The command prints the key's status. `updated_at` is the time of the change, as a Unix timestamp:

```
present: True
updated_at: 1795363151
```

**Step 2. Check that the key is stored.** Run the following command at any time. It prints the same two lines.

```
vijil-console pagerduty get
```

**Step 3. Send test events.** Console sends one Diamond test event and one Dome test event with your key.

```
vijil-console pagerduty test
```

The command prints the deduplication keys of the two events:

```
dedup_keys: [
  "vijil-test:diamond",
  "vijil-test:dome"
]
```

Your service shows two incidents whose titles start with `[Test]`:

* A Diamond red team result, at low urgency.
* A Dome block at the `test_event` control, at high urgency.

While they are open, repeat tests join them instead of opening new incidents.

**Step 4. Resolve the test incidents in PagerDuty before you rely on the integration.** If your service uses alert grouping, PagerDuty can add a real event to an open test incident when the two arrive close together.

Real events start within about 5 minutes. They include Diamond red team runs completed in the last 48 hours, so expect a low-urgency incident for each recent run that found something soon after you store the key. To replace the key, run Step 1 again; Console can use the old key for up to 5 minutes after the change.

### Troubleshooting

* **`No team selected`:** run `vijil-console team use <team ID>`.
* **`API error (403)`:** you are not a member of the selected team. Check the team with `vijil-console team list`.
* **`API error (404): Resource not found: Unable to find pagerduty_key` from `test`:** no key is stored for the selected team. Run Step 1.
* **`API error (502)` with `PagerDuty answered 400` from `test`:** PagerDuty rejected the key as invalid. Copy the **Integration Key** from the service's **Integrations** tab again and repeat Step 1.
* **`test` succeeds but no incidents appear:** PagerDuty accepts a well-formed key it does not recognize and then drops the events. Check that the key you stored is the **Integration Key** of this service, and repeat Step 1 if it is not.
* **`API error (503)`:** your Console cannot store or read team keys. Contact Vijil support, or the people who run your Console.
* **No incidents for real blocks or red team runs, though `test` works:** PagerDuty alerts may be turned off for your Console; see **Requirements**. Diamond pages only red team runs whose report lists at least one vulnerability, policy violation, or leaked artifact.

# How to Uninstall

**Step 1.** In Vijil, delete the stored key. The command asks you to confirm, then prints `Done.`

```
vijil-console pagerduty delete
```

Console stops sending events to your service within about 5 minutes.

**Step 2.** In PagerDuty, open your service, select the **Integrations** tab, and delete the **Vijil** integration. PagerDuty stops accepting events sent with its Integration Key.

**Step 3.** Resolve any open Vijil incidents in PagerDuty. Console never resolves them.
