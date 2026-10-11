from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from sniffer.analysis import analyze_packet, explain_protocol


def test_tcp_packet_metadata_includes_addresses_ports_size_and_payload_safety() -> None:
    packet = Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
        sport=51000, dport=443
    )

    result = analyze_packet(packet)

    assert result.src_ip == "192.0.2.10"
    assert result.dst_ip == "198.51.100.20"
    assert result.src_port == 51000
    assert result.dst_port == 443
    assert result.protocol == "TCP"
    assert result.size == len(packet)
    assert "payload is hidden" in result.details
    assert "Encrypted TLS/HTTPS payload hidden" in result.payload_preview
    assert result.timestamp


def test_plaintext_payload_preview_is_bounded() -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=9000)
        / Raw(load=b"A" * 140)
    )

    result = analyze_packet(packet)

    assert "A" * 96 in result.payload_preview
    assert "A" * 97 not in result.payload_preview
    assert "140 bytes total" not in result.payload_preview
    assert "96 bytes shown" in result.payload_preview


def test_http_payload_preview_omits_headers_and_body() -> None:
    packet = (
        Ether()
        / IP()
        / TCP(sport=50000, dport=80)
        / Raw(load=b"POST /login HTTP/1.1\r\nAuthorization: secret\r\n\r\npassword=hunter2")
    )

    result = analyze_packet(packet)

    assert "POST /login HTTP/1.1" in result.payload_preview
    assert "Authorization" not in result.payload_preview
    assert "hunter2" not in result.payload_preview


def test_dns_query_is_classified_and_domain_is_explained() -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.test"))
    )

    result = analyze_packet(packet)

    assert result.protocol == "DNS"
    assert result.src_port == 53000
    assert result.dst_port == 53
    assert "query" in result.details
    assert "example.test" in result.details
    assert "DNS query: example.test" in result.payload_preview


def test_icmp_and_udp_protocols_are_identified() -> None:
    icmp_result = analyze_packet(Ether() / IP() / ICMP(type=8))
    ipv6_icmp_result = analyze_packet(IPv6() / ICMPv6EchoRequest())
    udp_result = analyze_packet(Ether() / IP() / UDP(sport=1234, dport=5000))

    assert icmp_result.protocol == "ICMP"
    assert "echo request" in icmp_result.details
    assert ipv6_icmp_result.protocol == "ICMP"
    assert "echo request" in ipv6_icmp_result.details
    assert udp_result.protocol == "UDP"
    assert udp_result.src_port == 1234
    assert udp_result.dst_port == 5000


def test_protocol_explanations_have_a_safe_fallback() -> None:
    assert "connection" in explain_protocol("TCP")
    assert explain_protocol("Unknown") == "Protocol behavior is not classified by this basic sniffer."
