# Screenshot checklist

Save supervisor-ready captures in this directory. Do not include passwords, recovery keys, private addresses outside the lab, or unrelated personal data.

Captured dashboard images:

- `dashboard-overview.png`: dashboard title, selected log paths, and checksum caveat.
- `dashboard-events.png`: alert metrics, severity distribution, and recent event rows.

Additional terminal evidence can be captured for the supervisor:

- `fast-log-alerts.png`: terminal output from the three `grep -F` verification commands in the README.
- `eve-alerts.png`: EVE alert records showing `event_type`, signature, source/destination, and timestamp.

Record the capture date and test interface in the report. The saved dashboard images show the localhost demonstration. The separate `wlan0` smoke test verified ICMP only; do not imply the HTTP or TCP-burst demonstrations were run over Wi-Fi.