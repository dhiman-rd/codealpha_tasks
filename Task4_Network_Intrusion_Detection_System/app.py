import json
import os
import re
from collections import Counter, deque
from pathlib import Path

import streamlit as st


DEFAULT_EVE_LOG = Path(os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json"))
DEFAULT_FAST_LOG = Path(os.getenv("SURICATA_FAST_LOG", "/var/log/suricata/fast.log"))
MAX_RECENT_ALERTS = 500

FAST_LINE = re.compile(
    r"^(?P<timestamp>\S+)\s+\[\*\*\]\s+\[\d+:(?P<sid>\d+):\d+\]\s+"
    r"(?P<signature>.*?)\s+\[\*\*\].*?\[Priority: (?P<severity>\d+)\].*?"
    r"\{(?P<protocol>[^}]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dest>\S+)"
)


def severity_name(priority):
    try:
        priority = int(priority)
    except (TypeError, ValueError):
        return "Unknown"
    return {1: "Critical", 2: "High", 3: "Medium"}.get(priority, "Low")


def endpoint(address, port):
    if not address:
        return "-"
    return f"{address}:{port}" if port is not None else str(address)


def file_metadata(path):
    try:
        metadata = path.stat()
        return str(path), metadata.st_mtime_ns, metadata.st_size
    except OSError:
        return str(path), None, None


@st.cache_data(ttl=5, max_entries=8, show_spinner=False)
def read_eve(path_string, modified_ns, file_size):
    path = Path(path_string)
    total = 0
    by_severity = Counter()
    recent = deque(maxlen=MAX_RECENT_ALERTS)
    malformed = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue

                if event.get("event_type") != "alert":
                    continue

                alert = event.get("alert") or {}
                priority = alert.get("severity")
                severity = severity_name(priority)
                total += 1
                by_severity[severity] += 1
                recent.append(
                    {
                        "Timestamp": event.get("timestamp", "-"),
                        "Severity": severity,
                        "Source": endpoint(event.get("src_ip"), event.get("src_port")),
                        "Destination": endpoint(event.get("dest_ip"), event.get("dest_port")),
                        "Signature": alert.get("signature", "Unknown signature"),
                        "Category": alert.get("category", "Unclassified"),
                    }
                )
        return total, by_severity, list(reversed(recent)), malformed, None
    except FileNotFoundError:
        return 0, by_severity, [], malformed, f"EVE log not found: {path}"
    except PermissionError:
        return 0, by_severity, [], malformed, f"Permission denied reading EVE log: {path}"
    except OSError as error:
        return 0, by_severity, [], malformed, f"Could not read EVE log: {error}"


@st.cache_data(ttl=5, max_entries=8, show_spinner=False)
def read_fast(path_string, modified_ns, file_size):
    path = Path(path_string)
    recent = deque(maxlen=MAX_RECENT_ALERTS)
    total = 0
    by_severity = Counter()

    try:
        with path.open("r", encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                match = FAST_LINE.search(line)
                if not match:
                    continue
                values = match.groupdict()
                try:
                    severity = severity_name(values["severity"])
                    category_match = re.search(r"\[Classification: ([^\]]+)\]", line)
                    category = category_match.group(1) if category_match else "Unclassified"
                    source = values["src"]
                    destination = values["dest"]
                    total += 1
                    by_severity[severity] += 1
                    recent.append(
                        {
                            "Timestamp": values["timestamp"],
                            "Severity": severity,
                            "Source": source,
                            "Destination": destination,
                            "Signature": values["signature"],
                            "Category": category,
                        }
                    )
                except (AttributeError, TypeError, ValueError):
                    continue
        return total, by_severity, list(reversed(recent)), None
    except FileNotFoundError:
        return 0, Counter(), [], f"fast.log not found: {path}"
    except PermissionError:
        return 0, Counter(), [], f"Permission denied reading fast.log: {path}"
    except OSError as error:
        return 0, Counter(), [], f"Could not read fast.log: {error}"


def render_dashboard(eve_log_path, fast_log_path):
    eve_path = Path(eve_log_path)
    fast_path = Path(fast_log_path)
    eve_total, severity_counts, alerts, malformed, eve_error = read_eve(*file_metadata(eve_path))
    fast_total, fast_counts, fast_alerts, fast_error = read_fast(*file_metadata(fast_path))

    if eve_error:
        st.warning(eve_error)
    if malformed:
        st.warning(f"Skipped {malformed} malformed JSON line(s) in eve.json.")

    if eve_total:
        total_alerts = eve_total
        event_rows = alerts
        counts = severity_counts
        source_label = "eve.json"
    else:
        total_alerts = fast_total
        event_rows = fast_alerts
        counts = fast_counts
        source_label = "fast.log"
        if fast_error:
            st.info(fast_error)
        elif not fast_total:
            st.info("No alert events found yet. Start Suricata capture and generate authorized test traffic.")

    checksum_alerts = sum("invalid checksum" in row["Signature"].lower() for row in event_rows)
    if checksum_alerts:
        st.warning(
            f"{checksum_alerts} invalid-checksum alert(s) appear in recent events. "
            "Loopback offloading can cause checksum artifacts; verify before treating them as malicious."
        )

    st.caption(f"Alert source: {source_label} | EVE: {eve_path} | fast.log: {fast_path}")

    with st.container(horizontal=True):
        st.metric("Total alerts", total_alerts, border=True)
        st.metric("Critical", counts.get("Critical", 0), border=True)
        st.metric("High", counts.get("High", 0), border=True)
        st.metric(
            "Medium / Low",
            counts.get("Medium", 0) + counts.get("Low", 0),
            border=True,
        )

    chart_column, detail_column = st.columns([1, 2])
    with chart_column:
        st.subheader("Severity distribution")
        chart_data = {
            label: counts.get(label, 0)
            for label in ("Critical", "High", "Medium", "Low", "Unknown")
            if counts.get(label, 0)
        }
        if chart_data:
            st.bar_chart(
                chart_data,
                color="#b74436",
                alt="Alert count grouped by Suricata severity.",
            )
        else:
            st.caption("No severity data available.")

    with detail_column:
        st.subheader("Recent security events")
        if event_rows:
            st.dataframe(
                event_rows,
                width="stretch",
                hide_index=True,
                alt="Recent Suricata alerts with timestamps, endpoints, signatures, and categories.",
            )
        else:
            st.caption("Waiting for alert events.")


st.set_page_config(page_title="Suricata IDS", page_icon="S", layout="wide")
st.title("Network Intrusion Detection")
st.caption("SURICATA SENSOR  /  LIVE ALERT REVIEW")

with st.sidebar:
    st.subheader("Log sources")
    eve_log_path = st.text_input("EVE JSON", str(DEFAULT_EVE_LOG), key="eve_path")
    fast_log_path = st.text_input("Fast log", str(DEFAULT_FAST_LOG), key="fast_path")
    st.caption("Refreshes automatically every 5 seconds.")


@st.fragment(run_every=5)
def live_panel(eve_log_path, fast_log_path):
    render_dashboard(eve_log_path, fast_log_path)


live_panel(eve_log_path, fast_log_path)