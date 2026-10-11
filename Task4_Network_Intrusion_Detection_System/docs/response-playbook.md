# Alert response playbook

## Operating mode

This project is a passive IDS. Its local rules use `alert`; it does not issue `drop` or `reject`, and it does not change firewall rules. All containment actions below are manual and require authorization from the system or network owner.

## Triage

1. Record the alert timestamp, signature ID and name, category, severity, source, destination, protocol, and interface from `eve.json` or the dashboard.
2. Confirm the event is not from the localhost test, a duplicate Suricata process, or a known checksum/offload artifact. Preserve the original EVE and fast logs before rotating or changing anything.
3. Review nearby events for the same source and destination. Correlate with authorized endpoint, service, and network information; an IDS alert alone does not prove compromise.
4. For the HTTP test rule, confirm whether `/ids-test` was the controlled demonstration request. For a SYN-burst alert, determine whether the source performed an authorized inventory or scan.
5. Escalate unexplained high-severity activity to the lab supervisor or network owner with the preserved timestamps and relevant log lines.

## Authorized manual containment

Only after the owner confirms the event warrants containment:

1. Isolate the affected lab endpoint using the approved lab procedure, or ask the network administrator to apply a temporary firewall restriction.
2. Preserve relevant logs and endpoint evidence before cleanup. Note who approved containment and when it was applied.
3. Validate the service and endpoint state, remove the cause through the approved remediation process, and re-test in the authorized lab.
4. Restore connectivity only after the owner approves; record the action and outcome in the incident notes.

Do not run firewall-blocking commands as part of the demonstration. Automatic blocking is outside this project scope and remains disabled.