import base64
import json

import pytest

from ids.config import DecoderConfig
from tests.lab02.http_pcap_support import decode_http_pcap, write_http_pcap
from tests.lab02.reproduce_t02 import BODIES, EXPECTED, payloads, summarize


@pytest.mark.parametrize("policy", ["replace", "strict"])
def test_t02_http_text_entities_and_safe_continuation(tmp_path, policy):
    input_path = tmp_path / "input.pcap"
    output_path = tmp_path / "actual.jsonl"
    raw_payloads = payloads()
    write_http_pcap(input_path, raw_payloads)
    events = decode_http_pcap(input_path, output_path, DecoderConfig(invalid_bytes_policy=policy))
    saved = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert saved == events
    assert len(events) == 11
    assert summarize(events) == EXPECTED[policy]
    for event, body, payload in zip(events, BODIES, raw_payloads, strict=True):
        packet = event["packet"]
        fields = packet["application"]["fields"]
        assert packet["parse_status"] == "ok"
        assert base64.b64decode(packet["payload"]["base64"], validate=True) == payload
        raw_body = fields["body_base64"]
        assert (base64.b64decode(raw_body, validate=True) if raw_body is not None else b"") == body
        assert fields["body_length"] == len(body)
        if event["errors"]:
            assert event["reason"]
            assert all(error["stage"] == "decode" for error in event["errors"])
        else:
            assert event["reason"] is None
        assert event["preprocess_status"] is None
        assert event["flow"] is None
    assert events[3]["packet"]["application"]["fields"]["target"] == "/submit+entity?q=&lt;x&gt;"
    assert events[3]["decoded"]["http"]["uri"]["text"] == "/submit+entity?q=&lt;x&gt;"
    assert events[6]["decoded"]["http"]["html"]["text"] == "<next>"
    assert events[6]["decode_status"] == "ok"
    assert events[7]["decoded"]["http"]["html"] is None
    assert events[10]["decoded"]["http"]["html"]["text"] is None
