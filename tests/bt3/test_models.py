import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from ids.engine.models import (
    ContentCondition, ContentMatch, DetectionEvent, EngineInput, FlagsCondition,
    FlowCondition, FlowContext, MatchResult, MatchStatus, PortRange, Rule,
    RuleHeader, RuleStatus, SizeCondition,
)
from ids.flows.models import Endpoint, FlowDirection, FlowProtocol, FlowRecord, TcpState
from ids.models import CaptureSource, PacketEvent, PayloadInfo
from ids.output.jsonl import JsonlWriter
from ids.processing_models import ProcessedEvent


def test_rule_contract_keeps_conditions_order_binary_and_header_metadata():
    rule = Rule(
        RuleHeader("tcp", src_ip="10.0.0.0/24", dst_port=PortRange(80, 90), direction="<>"),
        100001, 1, "Test",
        contents=(ContentCondition(b"A\xff", nocase=True, offset=0, depth=10),
                  ContentCondition(b"B", distance=1, within=3)),
        flow=FlowCondition("to_server", True), flags=FlagsCondition(("SYN", "ACK")),
        dsize=SizeCondition(">", 0), source_file="rules/local.rules", source_line=1,
    )
    saved = json.loads(json.dumps(rule.to_dict()))
    assert saved["header"]["dst_port"] == {"start": 80, "end": 90}
    assert saved["header"]["direction"] == "<>"
    assert base64.b64decode(saved["contents"][0]["pattern"]["base64"]) == b"A\xff"
    assert saved["contents"][1]["distance"] == 1
    assert saved["flow"] == {"direction": "to_server", "established": True}
    assert saved["priority"] is saved["classtype"] is None


def test_engine_input_reuses_lab2_models_and_detaches_event_context_and_buffers():
    stamp = datetime(2026, 10, 25, tzinfo=timezone.utc)
    record = FlowRecord("flow-1", FlowProtocol.TCP, Endpoint("10.0.0.2", 51000),
                        Endpoint("10.0.0.1", 80), stamp, stamp, state=TcpState.NEW)
    context = FlowContext(record, FlowDirection.FORWARD)
    event = ProcessedEvent(PacketEvent(1, stamp.isoformat(), CaptureSource("pcap", "test.pcap"), 55,
                                      payload=PayloadInfo(1, "/w==")),
                           normalized={"transport": {"protocol": "TCP"}},
                           flow=record.association(FlowDirection.FORWARD))
    buffers = {"payload": b"\xff"}
    item = EngineInput(event, context, buffers)
    event.normalized["transport"]["protocol"] = "changed"
    record.state = context.record.state = TcpState.RESET
    buffers["payload"] = b"changed"
    saved = item.to_dict()
    assert saved["event"]["normalized"]["transport"]["protocol"] == "TCP"
    assert saved["flow"]["record"]["state"] == "NEW"
    assert saved["flow"]["record"]["duration"] == 0.0
    assert saved["flow"]["client"] is saved["flow"]["server"] is saved["flow"]["established"] is None
    assert saved["buffers"]["payload"] == {"base64": "/w==", "length": 1}
    saved["event"]["normalized"]["transport"]["protocol"] = "changed"
    assert item.event.normalized["transport"]["protocol"] == "TCP"


def test_empty_missing_and_independent_default_buffers_are_distinct():
    event = ProcessedEvent(PacketEvent(1, "2026-10-25T00:00:00Z", CaptureSource("pcap", "test"), 54))
    missing, another = EngineInput(event), EngineInput(event)
    empty = EngineInput(event, buffers={"payload": b""})
    missing.buffers["other"] = b"x"
    assert another.to_dict()["buffers"] == {}
    assert empty.to_dict()["buffers"] == {"payload": {"base64": "", "length": 0}}
    assert set(RuleStatus) == {"valid", "invalid", "unsupported"}
    assert MatchResult(1, 1, MatchStatus.SKIPPED, reason="flow_unknown").to_dict()["reason"] == "flow_unknown"


def test_detection_contract_writes_required_metadata_binary_match_info_and_utc(tmp_path):
    match = MatchResult(100001, 1, MatchStatus.MATCH,
                        contents=(ContentMatch(0, "payload", 2, 4, b"A\xff"),), checks=("header", "content"))
    result = DetectionEvent(datetime(2026, 10, 25, 7, tzinfo=timezone(timedelta(hours=7))),
                            100001, 1, "Nội dung đáng chú ý", Endpoint("10.0.0.2", 51000),
                            Endpoint("10.0.0.1", 80), FlowProtocol.TCP, "HTTP", "flow-1", match)
    path = tmp_path / "detection.jsonl"
    with JsonlWriter(path) as writer:
        writer.write(result)
    saved = json.loads(path.read_text())
    assert saved["timestamp"] == "2026-10-25T00:00:00.000000Z"
    assert (saved["sid"], saved["rev"], saved["msg"]) == (100001, 1, "Nội dung đáng chú ý")
    assert saved["src"] == {"ip": "10.0.0.2", "port": 51000}
    assert saved["dst"] == {"ip": "10.0.0.1", "port": 80}
    assert saved["protocol"] == "TCP" and saved["application_protocol"] == "HTTP" and saved["flow_id"] == "flow-1"
    assert saved["priority"] is saved["classtype"] is None
    assert base64.b64decode(saved["match"]["contents"][0]["pattern"]["base64"]) == b"A\xff"


def test_timestamp_export_does_not_guess_timezone():
    result = DetectionEvent(datetime(2026, 10, 25), 1, 1, "Test", Endpoint("10.0.0.2", 1),
                            Endpoint("10.0.0.1", 2), FlowProtocol.UDP, "DNS", None,
                            MatchResult(1, 1, MatchStatus.MATCH, checks=("header",)))
    with pytest.raises(ValueError, match="timezone"):
        result.to_dict()
