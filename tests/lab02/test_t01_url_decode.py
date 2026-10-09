import base64
import json

from ids.config import DecoderConfig
from tests.lab02.http_pcap_support import decode_http_pcap, write_http_pcap
from tests.lab02.reproduce_t01 import EXPECTED, TARGETS, payloads, summarize


def test_t01_pcap_url_decoding_keeps_raw_uri_and_payload(tmp_path):
    input_path = tmp_path / "input.pcap"
    output_path = tmp_path / "actual.jsonl"
    raw_payloads = payloads()
    write_http_pcap(input_path, raw_payloads)

    decode_http_pcap(input_path, output_path, DecoderConfig())
    events = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]

    assert len(events) == 5
    assert summarize(events) == EXPECTED
    for packet_id, (target, payload, saved) in enumerate(
        zip(TARGETS, raw_payloads, events, strict=True), 1
    ):
        packet = saved["packet"]
        assert packet["packet_id"] == packet_id
        assert packet["parse_status"] == "ok"
        assert packet["application"]["protocol"] == "HTTP"
        assert packet["application"]["fields"]["target"] == target.decode("ascii")
        assert base64.b64decode(packet["payload"]["base64"]) == payload
        assert saved["decoded"]["http"]["form"] is None
    assert events[3]["reason"]
    assert events[4]["errors"] == []
    assert events[4]["reason"] is None
