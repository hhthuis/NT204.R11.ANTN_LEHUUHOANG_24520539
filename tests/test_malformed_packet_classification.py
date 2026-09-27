from scapy.all import Ether, IP, Raw

from ids.models import CaptureSource
from ids.pipeline import parse_packet


SOURCE = CaptureSource(type="pcap", name="malformed-test.pcap")


def test_truncated_ipv4_header_is_malformed():
    raw_frame = bytes(
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
            type=0x0800,
        )
        / Raw(b"\x45\x00\x00\x14\x00\x01\x00\x00")
    )
    packet = Ether(raw_frame)

    event = parse_packet(packet, packet_id=1, source=SOURCE)

    assert event.parse_status == "malformed"
    assert event.network is None
    assert event.errors[0].stage == "network"
    assert "IPv4" in event.errors[0].message
    assert "truncated" in event.errors[0].message


def test_missing_tcp_header_is_malformed():
    raw_frame = bytes(
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / Raw(b"\x00\x50\x13\x88")
    )
    packet = Ether(raw_frame)

    event = parse_packet(packet, packet_id=2, source=SOURCE)

    assert event.parse_status == "malformed"
    assert event.network is not None
    assert event.transport is None
    assert event.errors[0].stage == "transport"
    assert "TCP" in event.errors[0].message
    assert "truncated" in event.errors[0].message
