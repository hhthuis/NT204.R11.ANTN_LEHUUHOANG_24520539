"""Build an updated flow summary without mutating the active record."""

from dataclasses import replace
from datetime import datetime, timezone

from ids.flows.models import FlowDirection, FlowProtocol, FlowRecord
from ids.preprocessors.validation import TCP_FLAGS


def update_statistics(
    flow: FlowRecord, *, direction: FlowDirection, timestamp: datetime,
    captured_length: int, flags: tuple[str, ...] = (), application_protocol: str = "UNKNOWN",
) -> FlowRecord:
    """Count each accepted observation, including retransmissions/empty payloads.

    A/B remain first-observed endpoints. Time bounds use UTC min/max, including
    out-of-order timestamps. First known application wins; flags do not change
    connection state. All calculations precede replacement of the active record.
    """
    direction = FlowDirection(direction)
    if type(captured_length) is not int or captured_length < 0:
        raise ValueError("Statistics require a nonnegative integer captured_length")
    if not isinstance(timestamp, datetime) or timestamp.utcoffset() is None:
        raise ValueError("Statistics require a timestamp with timezone")
    instant = timestamp.astimezone(timezone.utc)
    flag_set = set()
    if flow.protocol == FlowProtocol.TCP:
        if not isinstance(flags, (tuple, list)) or any(not isinstance(flag, str) or flag not in TCP_FLAGS for flag in flags):
            raise ValueError("Statistics require supported TCP flag names")
        flag_set = set(flags)
    application = flow.application_protocol
    if application == "UNKNOWN" and application_protocol in ("HTTP", "DNS", "SMTP", "MIME"):
        application = application_protocol
    forward = direction == FlowDirection.FORWARD
    return replace(
        flow,
        start_time=min(flow.start_time.astimezone(timezone.utc), instant),
        last_seen=max(flow.last_seen.astimezone(timezone.utc), instant),
        application_protocol=application,
        packet_count=flow.packet_count + 1,
        byte_count=flow.byte_count + captured_length,
        forward_packet_count=flow.forward_packet_count + int(forward),
        forward_byte_count=flow.forward_byte_count + (captured_length if forward else 0),
        backward_packet_count=flow.backward_packet_count + int(not forward),
        backward_byte_count=flow.backward_byte_count + (0 if forward else captured_length),
        syn_count=flow.syn_count + int("SYN" in flag_set),
        ack_count=flow.ack_count + int("ACK" in flag_set),
        fin_count=flow.fin_count + int("FIN" in flag_set),
        rst_count=flow.rst_count + int("RST" in flag_set),
    )
