# Network Intrusion Detection System

A passive Suricata IDS with project-owned signatures, real Suricata log review, and a local Streamlit dashboard. The custom rules alert only; this project does not change firewall policy or automatically block traffic.

## Project layout

```text
suricata/
  app.py
  requirements.txt
  rules/local.rules
  scripts/run_sensor.sh
  scripts/run_dashboard.sh
  scripts/test_traffic.py
  config/README.md
  docs/response-playbook.md
  logs/                 generated local test logs, optional
  screenshots/          captured demonstration images
  report.md
```

The sensor uses Kali's actual `/etc/suricata/suricata.yaml`, installed rules under `/var/lib/suricata/rules`, and default logs under `/var/log/suricata`. The project does not copy or replace the system YAML.

## Installation

Suricata 8.0.7 and `suricata-update` were already installed in the verified Kali environment. On a new Kali installation, install them with:

```bash
sudo apt update
sudo apt install suricata suricata-update
```

Before updating rules on a machine with existing data, inspect the updater's target first. In this environment `/var/lib/suricata/rules` was empty, so the standard ET Open rules were added with:

```bash
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Validate the project signatures as well:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -s "$PWD/rules/local.rules"
```

The installed YAML has `fast.log` and `eve.json` enabled and sets `/var/log/suricata/` as its log directory. Its AF_PACKET section names `eth0`; this host's active interface is `wlan0`. The project launcher therefore selects an interface explicitly with pcap mode instead of editing the system YAML.

## Choose an interface

List interfaces and addresses:

```bash
ip -brief link
ip -brief address
```

Choose an interface you own or are authorized to monitor. In the inspected environment `wlan0` was active and `eth0` was down. A three-ping smoke test on `wlan0` to the local gateway (`192.168.1.1`) produced three ICMP alerts. The HTTP and TCP-burst demonstrations use loopback (`lo`) only.

## Start monitoring

For authorized live monitoring, replace `wlan0` below with the selected interface:

```bash
sudo ./scripts/run_sensor.sh wlan0
```

This runs one foreground sensor process using `/etc/suricata/suricata.yaml`, adds `rules/local.rules`, and writes to the system log directory configured by Suricata. Leave this terminal running. Press Ctrl+C to stop it cleanly. Do not start multiple sensor instances against the same interface and log files.

The dashboard must run as your normal user, not with `sudo`:

```bash
./scripts/run_dashboard.sh
```

Open <http://127.0.0.1:8501>. The dashboard reads `/var/log/suricata/eve.json` and `/var/log/suricata/fast.log` by default and refreshes every five seconds. If a log file is unreadable, fix access through your local Suricata permissions policy; do not run the dashboard as root.

To install dashboard dependencies in the project virtual environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Safe localhost demonstration

Use localhost only for this test. It creates a project-local log set so it does not mix demonstration records with the system logs.

Terminal 1, start exactly one sensor in a new, unique project log directory:

```bash
sudo ./scripts/run_sensor.sh lo --local-logs=logs/final-demo --no-checksum
```

Terminal 2, generate ICMP, a marked HTTP request, and a 30-port TCP connect sweep against `127.0.0.1`:

```bash
.venv/bin/python scripts/test_traffic.py
```

Verify the fast log:

```bash
grep -E 'LOCAL ICMP echo request|LOCAL HTTP IDS test URI|LOCAL Possible TCP SYN scan or burst' logs/final-demo/fast.log
```

The verified run produced all three custom signatures in `fast.log` and `eve.json`; EVE contained no malformed JSON lines. The TCP rule alerts on a source's SYN burst, so repeated localhost connections can also trigger it; it is a heuristic rather than proof of a distinct-port scan. The test also recorded invalid-checksum alerts on loopback despite the `--no-checksum` option. Treat those as an unresolved capture/offload artifact, not proof of an intrusion. The dashboard shows logged events rather than filtering them.

The sensor launcher refuses to overwrite an existing `eve.json` or `fast.log`. For another run, choose a different empty path such as `logs/demo-02` and use the same path with `--project-logs` when starting the dashboard.

Stop the sensor with Ctrl+C after the test. Then start the dashboard against the project-local logs:

```bash
./scripts/run_dashboard.sh --project-logs=logs/final-demo
```

Use the dashboard to inspect timestamps, severity, source/destination, signatures, and categories. To verify a specific event directly:

```bash
grep -F 'LOCAL ICMP echo request' logs/final-demo/fast.log
grep -F 'LOCAL HTTP IDS test URI' logs/final-demo/fast.log
grep -F 'LOCAL Possible TCP SYN scan or burst' logs/final-demo/fast.log
```

## Response

Suricata is configured for detection and logging only. For analyst triage and authorized manual containment steps, see [docs/response-playbook.md](docs/response-playbook.md). No automatic firewall changes are made.

## Troubleshooting

- `No rule files match .../suricata.rules`: inspect `/var/lib/suricata/rules` and run `sudo suricata-update` if the configured ruleset is missing.
- `default-log-dir is not writable`: run the sensor with `sudo`; run the dashboard without `sudo`.
- Zero packets: verify the chosen interface with `ip -brief address`, ensure there is only one sensor, and use the project's explicit `--pcap=INTERFACE` launcher.
- Repeated alert records: check for duplicate Suricata processes with `ps -eo pid,comm,args | grep '[S]uricata-Main'`; stop only the project's extra capture processes with Ctrl+C.
- Many invalid-checksum events on loopback: loopback offloading can affect packet checksums. This environment still logged such events with the test checksum option enabled; do not silently discard them or interpret them as attacks without investigation.
- Dashboard says a log is missing: start Suricata first, or enter the correct log path in the dashboard sidebar. It handles absent files and malformed JSON without crashing.

## Screenshots and report

Capture the dashboard with the verified demo events visible and save it under `screenshots/`. See [screenshots/README.md](screenshots/README.md) for the capture checklist. The project report is [report.md](report.md).