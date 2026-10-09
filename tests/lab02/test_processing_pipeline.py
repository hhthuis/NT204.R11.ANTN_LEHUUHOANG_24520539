from copy import deepcopy

import pytest

from ids.config import ProcessingConfig, TrackerConfig
from ids.models import CaptureSource
from ids.processing_pipeline import ProcessingPipeline
from tests.lab02.udp_dns_support import make_dns_packet


class MemoryWriter:
    def __init__(self):
        self.rows = []

    def write(self, value):
        self.rows.append(deepcopy(value if isinstance(value, dict) else value.to_dict()))


def test_finish_batches_are_bounded_and_repeated_finish_does_not_duplicate_output():
    events, flows = MemoryWriter(), MemoryWriter()
    pipeline = ProcessingPipeline(ProcessingConfig(tracker=TrackerConfig(max_pending_summaries=1)), events, flows)
    for port in (53000, 53001, 53002):
        pipeline.process(make_dns_packet(client_port=port), CaptureSource("pcap", "input"))
    pipeline.finish()
    pipeline.finish()
    assert pipeline.packet_count == pipeline.flow_count == 3
    assert len({row["flow_id"] for row in flows.rows}) == 3
    assert pipeline.tracker.active_count == pipeline.tracker.pending_count == 0


def test_failed_flow_write_leaves_summary_pending_and_successful_retry_acks_once(monkeypatch):
    events, flows = MemoryWriter(), MemoryWriter()
    pipeline = ProcessingPipeline(ProcessingConfig(), events, flows)
    pipeline.process(make_dns_packet(), CaptureSource("pcap", "input"))

    def fail(value):
        raise OSError("disk full")

    with monkeypatch.context() as patch:
        patch.setattr(flows, "write", fail)
        with pytest.raises(OSError, match="disk full"):
            pipeline.finish()
    assert pipeline.tracker.pending_count == 1 and pipeline.flow_count == 0
    pipeline.finish()
    assert len(flows.rows) == pipeline.flow_count == 1 and pipeline.tracker.pending_count == 0


def test_skipped_unsupported_future_packet_does_not_advance_maintenance_clock():
    from scapy.all import Ether, ICMP, IP

    events, flows = MemoryWriter(), MemoryWriter()
    pipeline = ProcessingPipeline(ProcessingConfig(tracker=TrackerConfig(udp_idle_timeout=2)), events, flows)
    first = make_dns_packet()
    pipeline.process(first, CaptureSource("pcap", "input"))
    unsupported = Ether(src=first.src, dst=first.dst) / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP()
    unsupported.time = first.time + 100
    result = pipeline.process(unsupported, CaptureSource("pcap", "input"))
    assert result.flow is None and pipeline.tracker.active_count == 1 and flows.rows == []
    pipeline.finish()
    assert flows.rows[0]["end_reason"] == "capture_eof"


def test_capacity_eviction_is_written_before_eof_without_duplicate_summaries():
    events, flows = MemoryWriter(), MemoryWriter()
    pipeline = ProcessingPipeline(ProcessingConfig(tracker=TrackerConfig(max_active_flows=1)), events, flows)
    pipeline.process(make_dns_packet(), CaptureSource("pcap", "input"))
    pipeline.process(make_dns_packet(client_port=53001), CaptureSource("pcap", "input"))
    assert len(flows.rows) == 1 and flows.rows[0]["end_reason"] == "capacity_eviction"
    pipeline.finish()
    assert len(flows.rows) == 2 and flows.rows[1]["end_reason"] == "capture_eof"
