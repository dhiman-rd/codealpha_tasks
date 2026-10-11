# Configuration notes

Suricata's active system configuration is `/etc/suricata/suricata.yaml`. This project intentionally does not create a duplicate YAML file or overwrite the installed configuration.

The project adds signatures from `../rules/local.rules` using Suricata's command-line `-s` option. The run script uses `--pcap=INTERFACE` to explicitly select the requested capture interface because the inspected system YAML's AF_PACKET entry names `eth0`, which is down on this host.

Default output settings in the system YAML enable `fast.log` and `eve.json` under `/var/log/suricata/`. For controlled localhost demonstrations, the sensor script can override only the output directory with `-l logs/`; the dashboard has a matching `--project-logs` option.