"""Shared single-thread streaming pipeline for processed PCAP/live capture."""

from datetime import datetime

from ids.config import ProcessingConfig
from ids.decoders.decoder import decode_event
from ids.flows.tracker import FlowTracker
from ids.models import CaptureSource
from ids.output.jsonl import JsonlWriter
from ids.pipeline import parse_packet
from ids.preprocessors.preprocessor import preprocess_event
from ids.processing_models import ProcessingAction, ProcessedEvent


class ProcessingPipeline:
    def __init__(self, config: ProcessingConfig, events: JsonlWriter, flows: JsonlWriter):
        self.config, self.events, self.flows = config, events, flows
        self.tracker = FlowTracker(config.tracker)
        self.packet_count = self.flow_count = 0

    def write_pending(self) -> None:
        while self.tracker.pending_count:
            summary = self.tracker.pending_summary()
            self.flows.write(summary)
            # Failed output leaves this summary pending; never silently drop it.
            self.tracker.acknowledge_summary(summary["flow_id"])
            self.flow_count += 1

    def expire(self, now: datetime) -> None:
        self.write_pending()
        while self.tracker.expire(now):
            self.write_pending()

    def process(self, packet, source: CaptureSource) -> ProcessedEvent:
        parsed = parse_packet(packet, self.packet_count + 1, source)
        event = preprocess_event(decode_event(parsed, self.config.decoder), self.config.preprocessor)
        self.write_pending()
        saved = self.tracker.track(event)
        # A failed capacity plan committed nothing. Drain bounded expiry batches
        # and retry this uncounted observation; normal traffic respects sweep interval.
        if (event.processing_action == ProcessingAction.TRACK and saved.errors
                and saved.errors[-1].code == "tracker_summary_capacity"):
            self.expire(datetime.fromisoformat(event.normalized["timestamp"]))
            saved = self.tracker.track(event)
        self.events.write(saved)
        self.packet_count += 1
        self.write_pending()
        return saved

    def finish(self, reason="capture_eof", now: datetime | None = None) -> None:
        self.write_pending()
        while self.tracker.active_count:
            self.tracker.finish(reason, now)
            self.write_pending()
