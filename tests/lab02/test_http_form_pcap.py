import base64
import json

from ids.config import DecoderConfig
from tests.lab02.http_pcap_support import decode_http_pcap, write_http_pcap
from tests.lab02.reproduce_http_form import BODIES, EXPECTED, payloads, summarize


def test_form_pcap_preserves_raw_body_and_decodes_repeated_parameters(tmp_path):
    input_path = tmp_path / "input.pcap"
    output_path = tmp_path / "actual.jsonl"
    raw_payloads = payloads()
    write_http_pcap(input_path, raw_payloads)

    decode_http_pcap(input_path, output_path, DecoderConfig())
    events = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]

    assert len(events) == 7
    assert summarize(events) == EXPECTED
    for packet_id, (body, payload, saved) in enumerate(
        zip(BODIES, raw_payloads, events, strict=True), 1
    ):
        packet = saved["packet"]
        fields = packet["application"]["fields"]
        assert packet["packet_id"] == packet_id
        assert packet["parse_status"] == "ok"
        assert fields["target"] == "/submit"
        assert fields["body_length"] == len(body)
        if body:
            assert base64.b64decode(fields["body_base64"]) == body
        else:
            assert fields["body_base64"] is None
        assert base64.b64decode(packet["payload"]["base64"]) == payload
    assert events[2]["reason"]
    assert events[3]["reason"]
    assert events[4]["errors"] == []
    assert events[4]["reason"] is None
    assert events[5]["decoded"]["http"]["form"] is None
