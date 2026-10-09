import pytest

from ids.capture import live


class Socket:
    closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


def setup(monkeypatch):
    sock = Socket()
    monkeypatch.setattr(live, "get_if_list", lambda: ["mock0"])
    monkeypatch.setattr(live.conf, "L2listen", lambda **kwargs: sock)
    return sock


@pytest.mark.parametrize("has_packet", [False, True])
def test_live_uses_one_socket_ticks_without_packets_and_propagates_interrupt(monkeypatch, has_packet):
    sock = setup(monkeypatch)
    seen, ticks, calls = [], [], []

    def sniff(**kwargs):
        assert kwargs["opened_socket"] is sock and kwargs["store"] is False and kwargs["chainCC"] is True
        assert kwargs["timeout"] == 0.5
        calls.append(kwargs)
        if len(calls) == 2:
            raise KeyboardInterrupt
        if has_packet:
            kwargs["prn"]("packet")

    monkeypatch.setattr(live, "sniff", sniff)
    with pytest.raises(KeyboardInterrupt):
        live.capture_live_periodic("mock0", seen.append, lambda: ticks.append(1), 0.5)
    assert seen == (["packet"] if has_packet else []) and ticks == [1] and sock.closed


def test_callback_write_error_is_raised_outside_scapy_instead_of_being_swallowed(monkeypatch):
    sock = setup(monkeypatch)

    def fail(packet):
        raise OSError("disk full")

    def sniff(**kwargs):
        kwargs["prn"]("packet")  # callback returns without raising inside Scapy
        assert kwargs["stop_filter"]("packet") is True

    monkeypatch.setattr(live, "sniff", sniff)
    with pytest.raises(OSError, match="disk full"):
        live.capture_live_periodic("mock0", fail, lambda: None, 1)
    assert sock.closed


def test_timer_error_propagates_and_socket_is_closed(monkeypatch):
    sock = setup(monkeypatch)
    monkeypatch.setattr(live, "sniff", lambda **kwargs: None)

    def fail():
        raise ValueError("maintenance failed")

    with pytest.raises(ValueError, match="maintenance failed"):
        live.capture_live_periodic("mock0", lambda packet: None, fail, 1)
    assert sock.closed
