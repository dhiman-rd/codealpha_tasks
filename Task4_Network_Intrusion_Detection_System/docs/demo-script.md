# Supervisor demonstration script

## Short walkthrough

1. Introduce the project as a passive Suricata IDS using the installed system rules plus three local alert signatures.
2. Show `rules/local.rules` and explain the ICMP echo, `/ids-test` HTTP, and repeated TCP SYN detections. Point out that each action is `alert`, not `drop`.
3. Start one sensor on loopback with `sudo ./scripts/run_sensor.sh lo --local-logs=logs/final-demo --no-checksum`.
4. In another terminal, run `.venv/bin/python scripts/test_traffic.py`. This generates traffic only to `127.0.0.1`.
5. Show the three signature messages in `logs/final-demo/fast.log` and the corresponding JSON alert events in `logs/final-demo/eve.json`.
6. Stop the sensor with Ctrl+C and show the dashboard started with `./scripts/run_dashboard.sh --project-logs=logs/final-demo` at `http://127.0.0.1:8501`.
7. Explain the manual triage and containment process in `docs/response-playbook.md`, and note that no automatic blocking is enabled.

## Claims to keep precise

- The HTTP and TCP-burst test results use `lo`. A separate authorized `wlan0` smoke test verified three ICMP alerts to the local gateway.
- The localhost test produced invalid-checksum events associated with loopback offloading; they are documented and not presented as confirmed attacks.
- The SYN rule is a burst heuristic and also matched ordinary HTTPS connections during the WLAN smoke test; do not present those alerts as confirmed scans.
- No containment action or automatic blocking was tested or enabled.