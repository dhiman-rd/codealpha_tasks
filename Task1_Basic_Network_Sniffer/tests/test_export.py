import csv
from io import StringIO

from sniffer.analysis import PacketRecord
from sniffer.export import records_to_csv


def test_records_to_csv_includes_headers_and_packet_metadata() -> None:
    record = PacketRecord(
        timestamp="2026-10-11T12:00:00.000+00:00",
        src_ip="192.0.2.1",
        dst_ip="198.51.100.2",
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        size=60,
        details="ICMP echo request",
        payload_preview="test payload",
    )

    rows = list(csv.DictReader(StringIO(records_to_csv([record]))))

    assert len(rows) == 1
    assert rows[0]["src_ip"] == "192.0.2.1"
    assert rows[0]["src_port"] == ""
    assert rows[0]["protocol"] == "ICMP"
    assert rows[0]["size"] == "60"
    assert rows[0]["payload_preview"] == "test payload"
