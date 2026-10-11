# Network Intrusion Detection System

## Objective

Build a passive network intrusion detection system with Suricata, project-owned alert signatures, real-time log visualization, and a documented manual response process for an authorized lab.

## Tools

- Kali Linux Rolling 2025.3
- Suricata 8.0.7 and `suricata-update`
- Emerging Threats Open rules
- Python 3 and Streamlit 1.65.0 in a project virtual environment
- `tcpdump`, `ping`, and Python's standard HTTP and socket libraries for controlled localhost testing

## Methodology

The installed `/etc/suricata/suricata.yaml` was inspected and retained. Its default `fast.log` and `eve.json` outputs use `/var/log/suricata/`; the initial missing ET Open rules were downloaded with `suricata-update`, after confirming the configured rules directory was empty. The project signatures were loaded as additional rules with `-s`.

The system YAML's AF_PACKET entry names `eth0`, while the active interface observed during setup was `wlan0`. The project launcher uses Suricata's explicit pcap interface option and accepts an interface argument rather than editing the system configuration. A localhost-only generator provides ICMP, HTTP, and TCP connect-sweep traffic for repeatable rule checks.

The Streamlit dashboard reads the real EVE JSON and fast logs, refreshes every five seconds, reports severity totals, charts severity distribution, and shows recent endpoints, signatures, categories, and timestamps. It handles absent files, permission errors, and malformed JSON. The response workflow is manual; no automatic blocking is configured.

## Implementation

- `rules/local.rules`: ICMP echo request, `/ids-test` HTTP URI, and repeated TCP SYN rules.
- `scripts/run_sensor.sh`: selects one interface, uses the installed system YAML, and optionally writes test logs under `logs/`.
- `scripts/test_traffic.py`: generates controlled traffic only to `127.0.0.1`.
- `app.py`: local Streamlit dashboard using system logs by default or project logs for the demonstration.
- `docs/response-playbook.md`: alert triage and owner-approved manual containment procedure.

## Results

Rule syntax validation succeeded against the installed system rules. A localhost run using pcap capture verified all three custom signatures in `fast.log` and `eve.json`:

- ICMP echo request: signature ID `1000001`.
- HTTP `/ids-test`: signature ID `1000002`, HTTP response status `200`.
- TCP SYN burst: signature ID `1000003`; the local 30-port connect sweep produced matching alerts.
- EVE JSON parsing found zero malformed lines in the verified project log.

The final project-local EVE log parsed with zero malformed lines and contained 3 ICMP alerts, 1 HTTP test alert, 277 SYN-burst alerts, and 480 `SURICATA TCPv4 invalid checksum` events. Some burst alerts matched repeated localhost attempts to port 8501 while old browser tabs retried the stopped dashboard. The SYN rule is therefore a burst heuristic, not proof of distinct-port scanning. Suricata also warned about loopback offloading, and checksum alerts persisted despite the test's `--no-checksum` option. These events remain visible and are not claimed as malicious traffic.

A separate live-interface smoke test captured three ICMP echo requests on `wlan0` from `192.168.1.7` to the local gateway `192.168.1.1`; all three matched signature `1000001`, and EVE had zero malformed lines. That log also contained seven SYN-burst heuristic alerts to an HTTPS endpoint on port 443 and one `SURICATA STREAM TIMEWAIT ACK with wrong seq` event. They are recorded as observations, not confirmed attacks. HTTP and port-sweep rules were not tested on `wlan0`.

The dashboard server started at `http://127.0.0.1:8501` and rendered the real project-local EVE log using `./scripts/run_dashboard.sh --project-logs=logs/final-demo`. The overview and event-table screenshots are saved in `screenshots/dashboard-overview.png` and `screenshots/dashboard-events.png`.

## Limitations

- HTTP and SYN-burst demonstrations were loopback-only. `wlan0` was verified with a three-ping smoke test, not a broad network scan; capture visibility still depends on the selected interface and authorization.
- The current checksum alerts need further investigation before interpreting checksum-related events.
- The detector is passive and does not block traffic. Containment requires an authorized human operator.
- The dashboard is local-only and reads the active log files; rotated logs are not aggregated.

## Conclusion

The installed Suricata engine, standard rules, custom alert signatures, controlled traffic generator, log-backed dashboard, and manual response playbook form a working passive IDS demonstration. ICMP detection is verified on both loopback and `wlan0`; HTTP and TCP-burst detections are verified on loopback. The TCP rule is intentionally labeled as a possible burst because it also matches some ordinary connection bursts. Check checksum and stream anomalies in context before treating them as malicious.