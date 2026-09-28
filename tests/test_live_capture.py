import pytest
from scapy.all import Ether, IP, TCP

from ids.capture import live


def test_capture_live_forwards_packets_without_storing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="S"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(flags="SA"),
    ]
    received_packets = []

    monkeypatch.setattr(live, "get_if_list", lambda: ["lo", "eth0"])

    def fake_sniff(*, iface, prn, store):
        assert iface == "eth0"
        assert store is False

        for packet in packets:
            prn(packet)

    monkeypatch.setattr(live, "sniff", fake_sniff)

    live.capture_live("eth0", received_packets.append)

    assert len(received_packets) == 2
    assert received_packets[0] is packets[0]
    assert received_packets[1] is packets[1]


def test_capture_live_rejects_empty_interface() -> None:
    with pytest.raises(
        ValueError,
        match="Network interface name cannot be empty",
    ):
        live.capture_live("   ", lambda packet: None)


def test_capture_live_rejects_unknown_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live, "get_if_list", lambda: ["lo", "eth0"])

    with pytest.raises(
        ValueError,
        match="Network interface not found: wlan0",
    ):
        live.capture_live("wlan0", lambda packet: None)


def test_capture_live_stops_cleanly_on_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live, "get_if_list", lambda: ["eth0"])

    def interrupted_sniff(*, iface, prn, store):
        raise KeyboardInterrupt

    monkeypatch.setattr(live, "sniff", interrupted_sniff)

    live.capture_live("eth0", lambda packet: None)
