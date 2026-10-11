"""Packet metadata extraction and beginner-friendly protocol explanations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
    from scapy.packet import Raw
except ImportError:
    pass

PAYLOAD_PREVIEW_BYTES = 96
SENSITIVE_TEXT = re.compile(
    r"(?im)^([^\r\n]*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"password|passwd|token|api[-_ ]?key|secret)[^\r\n]*[:=])[^\r\n]*"
)
HTTP_REQUEST_LINE = re.compile(rb"^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|CONNECT)\s")
TLS_PORTS = {443, 853}


@dataclass(frozen=True)
class PacketRecord:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    size: int
    details: str
    payload_preview: str


def _payload_preview(packet: Any, src_port: int | None, dst_port: int | None) -> str:
    """Return a short plaintext preview while hiding TLS and HTTP bodies."""
    payload_layer = packet.getlayer(Raw)
    payload = bytes(payload_layer.load) if payload_layer is not None else b""

    if src_port in TLS_PORTS or dst_port in TLS_PORTS or (
        len(payload) >= 3
        and payload[0] in {20, 21, 22, 23}
        and payload[1] == 3
        and payload[2] <= 4
    ):
        return "Encrypted TLS/HTTPS payload hidden; metadata only."

    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        if packet.haslayer(DNSQR):
            name = packet[DNSQR].qname
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            label = "response" if int(dns_layer.qr) else "query"
            return f"DNS {label}: {str(name).rstrip('.')}"
        return f"DNS message ({len(bytes(dns_layer))} bytes); decoded details shown above."

    if not payload:
        return "No decoded application payload."

    if HTTP_REQUEST_LINE.match(payload):
        first_line = payload.splitlines()[0][:PAYLOAD_PREVIEW_BYTES]
        safe_line = first_line.decode("ascii", errors="replace")
        return f"HTTP plaintext request line: {safe_line} (headers/body omitted)"

    text = payload[:PAYLOAD_PREVIEW_BYTES].decode("utf-8", errors="replace")
    text = "".join(character if character.isprintable() else "." for character in text)
    text = SENSITIVE_TEXT.sub(r"\1 [redacted]", text)
    suffix = " …" if len(payload) > PAYLOAD_PREVIEW_BYTES else ""
    return f"{text}{suffix} [{min(len(payload), PAYLOAD_PREVIEW_BYTES)} bytes shown]"


def analyze_packet(packet: Any) -> PacketRecord:
    """Extract addressing, protocol, size, and a short explanation from a Scapy packet."""
    src_ip = "—"
    dst_ip = "—"
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

    src_port: int | None = None
    dst_port: int | None = None

    if packet.haslayer(TCP):
        transport = packet[TCP]
        src_port, dst_port = int(transport.sport), int(transport.dport)
        protocol = "TCP"
        details = "TCP connection data."
        if 443 in (src_port, dst_port):
            details = "TCP traffic on port 443 (likely HTTPS/TLS); payload is hidden."
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        src_port, dst_port = int(transport.sport), int(transport.dport)
        protocol = "UDP"
        details = "UDP datagram; delivery is connectionless and has no built-in retransmission."
    elif packet.haslayer(ICMP) or any(
        layer.__name__.startswith("ICMPv6") for layer in packet.layers()
    ):
        icmp_layer = packet.getlayer(ICMP)
        if icmp_layer is None:
            icmp_layer_type = next(
                layer
                for layer in packet.layers()
                if layer.__name__.startswith("ICMPv6")
            )
            icmp_layer = packet.getlayer(icmp_layer_type)
        protocol = "ICMP"
        icmp_types = {
            0: "echo reply",
            1: "destination unreachable",
            3: "destination unreachable",
            8: "echo request",
            128: "echo request",
            129: "echo reply",
        }
        details = f"ICMP {icmp_types.get(int(icmp_layer.type), f'type {icmp_layer.type}')}; used for network control and diagnostics."
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        protocol = "ARP"
        details = "Address Resolution Protocol maps a local IPv4 address to a link-layer address."
        src_ip, dst_ip = str(arp_layer.psrc), str(arp_layer.pdst)
    else:
        protocol = "Other"
        details = "Other or link-layer traffic; no supported network/transport layer was identified."

    if packet.haslayer(DNS) or src_port == 53 or dst_port == 53:
        protocol = "DNS"
        dns_layer = packet.getlayer(DNS)
        if dns_layer is not None and packet.haslayer(DNSQR):
            query_name = packet[DNSQR].qname
            if isinstance(query_name, bytes):
                query_name = query_name.decode("utf-8", errors="replace")
            query_name = str(query_name).rstrip(".")
            action = "response" if int(dns_layer.qr) else "query"
            details = f"DNS {action}" + (f" for {query_name}." if query_name else ".")
        else:
            details = "DNS traffic on port 53; DNS maps names to network records."

    timestamp_value = getattr(packet, "time", None)
    try:
        timestamp = datetime.fromtimestamp(
            float(timestamp_value), tz=timezone.utc
        ).astimezone().isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OSError, OverflowError):
        timestamp = datetime.now().astimezone().isoformat(timespec="milliseconds")

    return PacketRecord(
        timestamp=timestamp,
        src_ip=str(src_ip),
        dst_ip=str(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        size=len(packet),
        details=details,
        payload_preview=_payload_preview(packet, src_port, dst_port),
    )


def explain_protocol(protocol: str) -> str:
    """Return a concise explanation suitable for the dashboard."""
    explanations = {
        "TCP": "Reliable, ordered transport that establishes a connection before exchanging data.",
        "UDP": "Connectionless transport with low overhead; delivery and ordering are not guaranteed.",
        "ICMP": "Network control and diagnostic messages, including the messages used by ping.",
        "DNS": "Name-resolution traffic that translates domain names into network records.",
        "ARP": "Local IPv4-to-link-layer address discovery on an Ethernet network.",
        "Other": "Traffic whose network or transport protocol is not classified by this basic sniffer.",
    }
    return explanations.get(protocol, "Protocol behavior is not classified by this basic sniffer.")
