import base64
import json

import pytest

from ids.config import DecoderConfig
from tests.lab02.reproduce_t03 import EXPECTED, WIRE_BODIES, payloads, summarize
from tests.lab02.smtp_pcap_support import decode_smtp_pcap, write_smtp_pcap


@pytest.mark.parametrize("policy", ["replace", "strict"])
def test_t03_base64_qp_and_safe_message_continuation(tmp_path, policy):
    input_path = tmp_path / "input.pcap"
    output_path = tmp_path / "actual.jsonl"
    raw_payloads = payloads()
    write_smtp_pcap(input_path, raw_payloads)
    events = decode_smtp_pcap(input_path, output_path, DecoderConfig(invalid_bytes_policy=policy))
    saved = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert saved == events and len(events) == 14
    assert summarize(events) == EXPECTED[policy]
    for event, wire_body, payload in zip(events, WIRE_BODIES, raw_payloads, strict=True):
        packet = event["packet"]
        assert packet["application"]["protocol"] == "SMTP"
        assert packet["application"]["kind"] == "message"
        fields = packet["application"]["fields"]
        assert base64.b64decode(packet["payload"]["base64"], validate=True) == payload
        raw = fields["body_base64"]
        assert (base64.b64decode(raw, validate=True) if raw is not None else b"") == wire_body
        assert fields["body_length"] == len(wire_body)
        assert base64.b64decode(fields["headers_base64"], validate=True) == payload.split(b"\r\n\r\n", 1)[0]
        if event["errors"]:
            assert event["reason"] and all(error["stage"] == "decode" for error in event["errors"])
        else:
            assert event["reason"] is None
        assert event["preprocess_status"] is None and event["flow"] is None
    assert events[7]["decode_status"] == "ok" and events[7]["decoded"]["mime"]["text"] == "OK"
    assert events[9]["decoded"]["mime"]["text"] is None
    assert events[12]["decoded"]["mime"]["body_length"] == 0
    assert events[13]["packet"]["parse_status"] == "partial"
