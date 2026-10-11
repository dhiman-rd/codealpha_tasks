#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
config="/etc/suricata/suricata.yaml"
rules="$project_dir/rules/local.rules"

if [[ $# -lt 1 ]]; then
    printf 'Usage: sudo %s INTERFACE [--local-logs[=PATH]] [--no-checksum]\n' "$0"
    printf '\nAvailable interfaces:\n'
    ip -brief address
    exit 2
fi
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    printf 'Usage: sudo %s INTERFACE [--local-logs[=PATH]] [--no-checksum]\n' "$0"
    printf '\nAvailable interfaces:\n'
    ip -brief address
    exit 0
fi

interface="$1"
shift
local_log_dir=""
no_checksum=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local-logs) local_log_dir="$project_dir/logs" ;;
        --local-logs=*) local_log_dir="${1#*=}" ;;
        --no-checksum) no_checksum=true ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [[ $EUID -ne 0 ]]; then
    printf 'Run this capture script with sudo. The dashboard should run without sudo.\n' >&2
    exit 1
fi
if pgrep -x Suricata-Main >/dev/null; then
    printf 'A Suricata engine is already running. Stop it before starting another sensor.\n' >&2
    exit 1
fi
if [[ ! -r "$config" || ! -r "$rules" ]]; then
    printf 'Cannot read Suricata config or project rules.\n' >&2
    exit 1
fi
if ! ip link show dev "$interface" >/dev/null 2>&1; then
    printf 'Interface not found: %s\n' "$interface" >&2
    exit 1
fi

suricata_args=(-c "$config" "--pcap=$interface" -s "$rules")
if [[ -n "$local_log_dir" ]]; then
    if [[ "$local_log_dir" != /* ]]; then
        local_log_dir="$project_dir/$local_log_dir"
    fi
    if [[ -e "$local_log_dir/eve.json" || -e "$local_log_dir/fast.log" ]]; then
        printf 'Refusing to overwrite existing logs in %s. Choose a new --local-logs=PATH.\n' "$local_log_dir" >&2
        exit 1
    fi
    mkdir -p "$local_log_dir"
    suricata_args+=(-l "$local_log_dir")
    printf 'Writing demo logs to %s\n' "$local_log_dir"
else
    printf 'Using the system log directory configured in %s\n' "$config"
fi
if [[ "$no_checksum" == true ]]; then
    suricata_args+=(-k none)
    printf 'Checksum validation is disabled for this capture.\n'
fi

printf 'Capturing on %s. Press Ctrl+C to stop this sensor.\n' "$interface"
exec suricata "${suricata_args[@]}"