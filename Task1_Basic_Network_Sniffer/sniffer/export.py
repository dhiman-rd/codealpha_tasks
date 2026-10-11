"""Export captured packet metadata in a spreadsheet-friendly CSV format."""

from __future__ import annotations

import csv
from io import StringIO
from typing import Iterable

from .analysis import PacketRecord


CSV_FIELDS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "size",
    "details",
    "payload_preview",
)


def records_to_csv(records: Iterable[PacketRecord]) -> str:
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for record in records:
        writer.writerow(
            {
                "timestamp": record.timestamp,
                "src_ip": record.src_ip,
                "dst_ip": record.dst_ip,
                "src_port": record.src_port if record.src_port is not None else "",
                "dst_port": record.dst_port if record.dst_port is not None else "",
                "protocol": record.protocol,
                "size": record.size,
                "details": record.details,
                "payload_preview": record.payload_preview,
            }
        )
    return output.getvalue()
