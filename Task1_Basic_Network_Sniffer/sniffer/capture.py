"""Threaded Scapy capture with safe start/stop and bounded metadata storage."""

from __future__ import annotations

from collections import Counter, deque
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any

from .analysis import PacketRecord, analyze_packet

try:
    from scapy.all import PcapWriter, get_if_list, sniff

    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = ""
except ImportError as exc:
    PcapWriter = Any  # type: ignore[misc,assignment]
    get_if_list = None
    sniff = None
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(exc)


class CaptureManager:
    """Own one capture thread and the coresponding packet metadata."""

    def __init__(self, max_records: int = 5_000) -> None:
        self._records: deque[PacketRecord] = deque(maxlen=max_records)
        self._protocol_counts: Counter[str] = Counter()
        self._packet_count = 0
        self._lock = Lock()
        self._stop_event = Event()
        self._thread: Thread | None = None   #jisse streamlit freeze na ho 
        self._writer: Any = None
        self._active = False
        self._error: str | None = None
        self._pcap_path: str | None = None

    @staticmethod
    def available_interfaces() -> list[str]:
        if not SCAPY_AVAILABLE or get_if_list is None:
            return []
        return sorted(set(get_if_list()))

    def start(self, interface: str, pcap_path: str | None = None) -> None:
        if not SCAPY_AVAILABLE or sniff is None:  #packet capture hoga toh yeh chlega 
            raise RuntimeError(f"Scapy is not available: {SCAPY_IMPORT_ERROR}")
        if not interface:
            raise ValueError("Select a network interface before starting capture.")
        if interface not in self.available_interfaces():
            raise ValueError(
                f"Interface {interface!r} is not available. Refresh the interface list and try again."
            )

        with self._lock:
            if self._active:
                raise RuntimeError("Packet capture is already running.")
            self._error = None
            self._pcap_path = None
            self._stop_event.clear()

            if pcap_path:
                destination = Path(pcap_path).expanduser()
                if not destination.name:
                    raise ValueError("Enter a valid PCAP output file path.")
                destination.parent.mkdir(parents=True, exist_ok=True)
                self._writer = PcapWriter(str(destination), append=False, sync=True)
                self._pcap_path = str(destination)

            self._active = True
            self._thread = Thread(
                target=self._capture_loop,
                args=(interface,),
                name="scapy-packet-capture",
                daemon=True,
            )
            try:
                self._thread.start()
            except Exception:
                self._active = False
                self._close_writer()
                raise

    def stop(self, timeout: float = 3.0) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                return
            self._stop_event.set()
        thread.join(timeout=timeout)
        if thread.is_alive():
            raise RuntimeError("Capture is still stopping. Please wait and try again.")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "records": list(self._records),
                "protocol_counts": dict(self._protocol_counts),
                "packet_count": self._packet_count,
                "active": self._active,
                "error": self._error,
                "pcap_path": self._pcap_path,
            }

    def _capture_loop(self, interface: str) -> None:
        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=interface,
                    prn=self._handle_packet, #packet milne ke bad konsa function call hoga
                    store=False,
                    timeout=1,
                )
        except Exception as exc:
            with self._lock:
                self._error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._active = False
                self._close_writer()

    def _handle_packet(self, packet: Any) -> None:
        record = analyze_packet(packet)
        with self._lock:
            self._records.append(record)
            self._protocol_counts[record.protocol] += 1
            self._packet_count += 1
            if self._writer is not None:
                try:
                    self._writer.write(packet)
                except Exception as exc:
                    self._error = f"PCAP write failed ({type(exc).__name__}): {exc}"
                    self._stop_event.set()

    def _close_writer(self) -> None:
        writer = self._writer
        self._writer = None
        if writer is not None:
            try:
                writer.close()
            except Exception as exc:
                self._error = f"PCAP close failed ({type(exc).__name__}): {exc}"
