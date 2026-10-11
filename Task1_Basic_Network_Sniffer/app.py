"""Streamlit dashboard for authorized, metadata-only packet monitoring."""

from __future__ import annotations

import streamlit as st

from sniffer.analysis import PacketRecord, explain_protocol
from sniffer.capture import (
    SCAPY_AVAILABLE,
    SCAPY_IMPORT_ERROR,
    CaptureManager,
)
from sniffer.export import records_to_csv


st.set_page_config(page_title="Basic Network Sniffer", page_icon="📡", layout="wide")
st.title("📡 Basic Network Sniffer")
st.caption("Live packet metadata for networks and devices you own or are authorized to monitor.")
st.warning(
    "Use only on networks you own or have explicit permission to monitor. "
    "Plaintext payload previews are limited; HTTPS/TLS payloads are hidden and not decrypted. "
    "Packet previews and PCAP files may contain sensitive information."
)

if not SCAPY_AVAILABLE:
    st.error(f"Scapy could not be loaded: {SCAPY_IMPORT_ERROR}")
    st.code("python -m pip install -r requirements.txt")
    st.stop()

if "capture_manager" not in st.session_state:
    st.session_state.capture_manager = CaptureManager()
manager: CaptureManager = st.session_state.capture_manager
state = manager.snapshot()

try:
    interfaces = manager.available_interfaces()
except Exception as exc:
    interfaces = []
    st.error(f"Could not list network interfaces ({type(exc).__name__}): {exc}")

if not interfaces:
    st.error("No network interfaces were found. Check the interface name and try `ip link` in a terminal.")

left, right = st.columns([2, 3])
with left:
    default_interface = "wlan0" if "wlan0" in interfaces else (interfaces[0] if interfaces else None)
    selected_interface = st.selectbox(
        "Network interface",
        interfaces,
        index=interfaces.index(default_interface) if default_interface else None,
        placeholder="No interfaces available",
        disabled=state["active"] or not interfaces,
        help="Choose wlan0 when available, or another interface you are authorized to monitor.",
    )
with right:
    save_pcap = st.checkbox(
        "Save captured packets to a local PCAP file",
        disabled=state["active"],
        help="PCAP files contain the captured packets, including payloads. Store and share them carefully.",
    )
    pcap_path = st.text_input(
        "PCAP file path",
        value="captures/network-capture.pcap",
        disabled=state["active"] or not save_pcap,
    )

start_col, stop_col, status_col = st.columns([1, 1, 4])
with start_col:
    if st.button("Start capture", type="primary", disabled=state["active"] or not interfaces):
        try:
            manager.start(
                selected_interface or "",
                pcap_path=pcap_path.strip() if save_pcap else None,
            )
            st.rerun()
        except PermissionError as exc:
            st.error(
                f"Capture permission denied: {exc} "
                "Run Streamlit with sudo, or configure authorized packet-capture capabilities."
            )
        except Exception as exc:
            st.error(f"Could not start capture ({type(exc).__name__}): {exc}")
with stop_col:
    if st.button("Stop capture", disabled=not state["active"]):
        try:
            manager.stop()
            st.rerun()
        except Exception as exc:
            st.error(f"Could not stop capture ({type(exc).__name__}): {exc}")
with status_col:
    if state["active"]:
        st.success(f"Capturing on {selected_interface or 'selected interface'}")
    else:
        st.info("Capture is stopped. Start capture to collect packets; the dashboard refreshes automatically.")


def render_dashboard(capture_manager: CaptureManager) -> None:
    snapshot = capture_manager.snapshot()
    records: list[PacketRecord] = snapshot["records"]
    if snapshot["error"]:
        error_message = snapshot["error"]
        if any(word in error_message.lower() for word in ("permission", "operation not permitted", "socket")):
            st.error(
                f"Capture error: {error_message}. Check capture permissions and confirm the interface is active."
            )
        else:
            st.error(f"Capture error: {error_message}")
    if snapshot["pcap_path"]:
        st.caption(f"PCAP output: `{snapshot['pcap_path']}`")

    protocol_counts = snapshot["protocol_counts"]
    total_col, shown_col, protocol_col = st.columns(3)
    total_col.metric("Packets captured", snapshot["packet_count"])
    shown_col.metric("Packets in dashboard", len(records), "most recent 5,000 maximum")
    protocol_col.metric("Protocols observed", len(protocol_counts))

    if protocol_counts:
        st.subheader("Protocol distribution")
        st.bar_chart(protocol_counts)

    st.subheader("Filter and inspect packets")
    protocol_options = ["All"] + sorted({record.protocol for record in records})
    ip_options = sorted(
        {
            address
            for record in records
            for address in (record.src_ip, record.dst_ip)
            if address != "—"
        }
    )
    protocol_filter, source_filter, destination_filter, port_filter = st.columns(4)
    selected_protocol = protocol_filter.selectbox("Protocol", protocol_options)
    selected_source = source_filter.selectbox("Source IP", ["All"] + ip_options)
    selected_destination = destination_filter.selectbox("Destination IP", ["All"] + ip_options)
    selected_port = port_filter.number_input("Port (either side)", min_value=0, max_value=65535, value=0)

    filtered = [
        record
        for record in records
        if (selected_protocol == "All" or record.protocol == selected_protocol)
        and (selected_source == "All" or record.src_ip == selected_source)
        and (selected_destination == "All" or record.dst_ip == selected_destination)
        and (
            selected_port == 0
            or selected_port in (record.src_port, record.dst_port)
        )
    ]
    st.caption(f"Showing {len(filtered)} matching packets out of {len(records)} retained records.")

    if filtered:
        rows = [
            {
                "Timestamp": record.timestamp,
                "Source IP": record.src_ip,
                "Source port": record.src_port if record.src_port is not None else "—",
                "Destination IP": record.dst_ip,
                "Destination port": record.dst_port if record.dst_port is not None else "—",
                "Protocol": record.protocol,
                "Size (bytes)": record.size,
                "Analysis": record.details,
                "Payload preview": record.payload_preview,
            }
            for record in filtered
        ]
        st.dataframe(rows, width="stretch", hide_index=True)
        st.download_button(
            "Download filtered packet details (CSV)",
            data=records_to_csv(filtered),
            file_name="network-packets.csv",
            mime="text/csv",
        )
    else:
        st.info("No packets match the current filters yet.")

    if protocol_counts:
        st.subheader("What the traffic means")
        for protocol, count in sorted(protocol_counts.items()):
            st.write(f"**{protocol} — {count} packet(s):** {explain_protocol(protocol)}")
    st.caption(
        "Payload previews are limited to 96 bytes and are for authorized demonstrations only. "
        "TLS/HTTPS payloads are hidden; encrypted application content is not read or decrypted."
    )


st.fragment(run_every="2s")(render_dashboard)(manager)
