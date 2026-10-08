import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from ids.flows.models import (
    Endpoint,
    FlowDirection,
    FlowKey,
    FlowProtocol,
    FlowRecord,
    TcpState,
)
from ids.models import CaptureSource, PacketEvent
from ids.processing_models import ProcessedEvent


def make_flow(**overrides) -> FlowRecord:
    start = datetime(2026, 10, 9, tzinfo=timezone.utc)
    fields = {
        "flow_id": "test-flow-1",
        "protocol": FlowProtocol.TCP,
        "endpoint_a": Endpoint("10.0.0.2", 51000),
        "endpoint_b": Endpoint("10.0.0.1", 80),
        "start_time": start,
        "last_seen": start,
        "state": TcpState.NEW,
    }
    fields.update(overrides)
    return FlowRecord(**fields)


def test_flow_summary_round_trips_all_required_statistics_and_utc_times():
    flow = make_flow(
        application_protocol="HTTP",
        last_seen=datetime(2026, 10, 9, 0, 0, 2, 500000, tzinfo=timezone.utc),
        packet_count=5,
        byte_count=400,
        forward_packet_count=3,
        forward_byte_count=240,
        backward_packet_count=2,
        backward_byte_count=160,
        syn_count=2,
        ack_count=4,
        fin_count=0,
        rst_count=0,
        state=TcpState.ESTABLISHED,
    )

    saved = json.loads(json.dumps(flow.to_dict()))

    assert saved == {
        "flow_id": "test-flow-1",
        "protocol": "TCP",
        "application_protocol": "HTTP",
        "endpoint_a": {"ip": "10.0.0.2", "port": 51000},
        "endpoint_b": {"ip": "10.0.0.1", "port": 80},
        "start_time": "2026-10-09T00:00:00.000000Z",
        "last_seen": "2026-10-09T00:00:02.500000Z",
        "duration": 2.5,
        "packet_count": 5,
        "byte_count": 400,
        "forward_packet_count": 3,
        "forward_byte_count": 240,
        "backward_packet_count": 2,
        "backward_byte_count": 160,
        "syn_count": 2,
        "ack_count": 4,
        "fin_count": 0,
        "rst_count": 0,
        "state": "ESTABLISHED",
    }


def test_udp_summary_has_no_tcp_state_and_converts_local_time_to_utc():
    local = timezone(timedelta(hours=7))
    start = datetime(2026, 10, 9, 7, tzinfo=local)
    flow = make_flow(
        protocol=FlowProtocol.UDP,
        state=None,
        start_time=start,
        last_seen=start + timedelta(milliseconds=125),
    )

    saved = json.loads(json.dumps(flow.to_dict()))

    assert saved["state"] is None
    assert saved["protocol"] == "UDP"
    assert saved["syn_count"] == saved["ack_count"] == 0
    assert saved["fin_count"] == saved["rst_count"] == 0
    assert saved["start_time"] == "2026-10-09T00:00:00.000000Z"
    assert saved["duration"] == 0.125


@pytest.mark.parametrize("field_name", ["start_time", "last_seen"])
def test_flow_rejects_ambiguous_timestamps_without_timezone(field_name):
    with pytest.raises(ValueError, match=f"{field_name} must be timezone-aware"):
        make_flow(**{field_name: datetime(2026, 10, 9)})


def test_flow_rejects_initial_last_seen_before_start_time():
    with pytest.raises(ValueError, match="last_seen cannot be earlier"):
        make_flow(last_seen=datetime(2026, 10, 8, tzinfo=timezone.utc))


def test_duration_uses_elapsed_time_across_daylight_saving_clock_change():
    local = ZoneInfo("America/New_York")
    flow = make_flow(
        start_time=datetime(2026, 11, 1, 1, 50, tzinfo=local, fold=0),
        last_seen=datetime(2026, 11, 1, 1, 10, tzinfo=local, fold=1),
    )

    assert flow.duration == 1200.0
    saved = flow.to_dict()
    assert saved["start_time"] == "2026-11-01T05:50:00.000000Z"
    assert saved["last_seen"] == "2026-11-01T06:10:00.000000Z"


def test_flow_key_matches_reverse_endpoints_without_reordering_record_direction():
    flow = make_flow()
    forward = FlowKey(flow.protocol, flow.endpoint_a, flow.endpoint_b)
    backward = FlowKey(flow.protocol, flow.endpoint_b, flow.endpoint_a)
    different_transport = FlowKey(
        FlowProtocol.UDP, flow.endpoint_a, flow.endpoint_b
    )
    different_port = FlowKey(
        flow.protocol, Endpoint(flow.endpoint_a.ip, 51001), flow.endpoint_b
    )

    assert forward == backward
    assert {forward: "same-flow"}[backward] == "same-flow"
    assert forward != different_transport
    assert forward != different_port
    assert flow.endpoint_a == Endpoint("10.0.0.2", 51000)


def test_processed_event_keeps_flow_state_snapshot_after_record_changes():
    flow = make_flow()
    packet = PacketEvent(
        packet_id=1,
        timestamp="2026-10-09T00:00:00Z",
        source=CaptureSource("pcap", "test.pcap"),
        captured_length=60,
    )
    event = ProcessedEvent(
        packet=packet, flow=flow.association(FlowDirection.FORWARD)
    )

    flow.state = TcpState.ESTABLISHED
    flow.last_seen += timedelta(seconds=1)
    later = flow.association(FlowDirection.BACKWARD)

    saved = json.loads(json.dumps(event.to_dict()))
    assert saved["flow"] == {
        "flow_id": "test-flow-1",
        "direction": "forward",
        "state": "NEW",
    }
    assert later.flow_id == event.flow.flow_id
    assert later.state == TcpState.ESTABLISHED
    assert later.direction == FlowDirection.BACKWARD
    assert flow.duration == 1.0
    with pytest.raises(FrozenInstanceError):
        event.flow.state = TcpState.RESET


def test_exported_summary_and_endpoints_do_not_allow_mutating_key_identity():
    flow = make_flow()
    key = FlowKey(flow.protocol, flow.endpoint_a, flow.endpoint_b)
    table = {key: flow.flow_id}

    exported = flow.to_dict()
    exported["endpoint_a"]["port"] = 12345

    assert flow.endpoint_a.port == 51000
    assert table[key] == "test-flow-1"
    with pytest.raises(FrozenInstanceError):
        flow.endpoint_a.port = 12345
