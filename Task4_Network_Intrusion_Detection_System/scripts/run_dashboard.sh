#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"

if [[ ! -x "$project_dir/.venv/bin/streamlit" ]]; then
    printf 'Dashboard dependencies are missing. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n' >&2
    exit 1
fi

if [[ "${1:-}" == "--project-logs" || "${1:-}" == --project-logs=* ]]; then
    log_dir="$project_dir/logs"
    if [[ "$1" == --project-logs=* ]]; then
        log_dir="${1#*=}"
        if [[ "$log_dir" != /* ]]; then
            log_dir="$project_dir/$log_dir"
        fi
    fi
    export SURICATA_EVE_LOG="$log_dir/eve.json"
    export SURICATA_FAST_LOG="$log_dir/fast.log"
    shift
fi
if [[ $# -gt 0 ]]; then
    printf 'Usage: %s [--project-logs[=PATH]]\n' "$0" >&2
    exit 2
fi

exec "$project_dir/.venv/bin/streamlit" run "$project_dir/app.py" \
    --server.address 127.0.0.1 \
    --server.port "${SURICATA_DASHBOARD_PORT:-8501}"