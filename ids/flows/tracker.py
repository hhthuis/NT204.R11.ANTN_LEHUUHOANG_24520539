"""Single-stream flow identity, TCP states, idle expiry and bounded queues."""

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from ipaddress import ip_address

from ids.config import CapacityPolicy, TrackerConfig
from ids.flows.expiry import idle_timeout, is_expired, utc_time
from ids.flows.models import Endpoint, FlowDirection, FlowKey, FlowProtocol, FlowRecord, TcpState
from ids.flows.statistics import update_statistics
from ids.flows.tcp import TcpClose, TcpHandshake, update_close, update_handshake
from ids.preprocessors.validation import TCP_FLAGS, validate_packet
from ids.processing_models import (
    PreprocessStatus, ProcessedEvent, ProcessingAction, ProcessingError, ProcessingStage,
)


def make_flow_id(key: FlowKey, generation: int = 1) -> str:
    """Stable across directions, processes and replay of the same flow lifetimes.

    Generation is local to a key, so unrelated flow creation order cannot alter
    an ID. Removing and recreating a key in this tracker starts a new lifetime.
    A fresh tracker resets generations; these IDs are not global capture IDs.
    """
    if type(generation) is not int or generation < 1:
        raise ValueError("Flow generation must be a positive integer")
    value = ["flow-v1", key.protocol.value,
             [key.endpoint_low.ip, key.endpoint_low.port],
             [key.endpoint_high.ip, key.endpoint_high.port], generation]
    canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return "flow-" + hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class _TrackingInput:
    key: FlowKey
    src: Endpoint
    dst: Endpoint
    timestamp: datetime
    application: str
    captured_length: int
    flags: tuple[str, ...]


def _tracking_input(event: ProcessedEvent) -> _TrackingInput:
    if event.preprocess_status not in (PreprocessStatus.VALID, PreprocessStatus.PARTIAL):
        raise ValueError("Tracking requires a validated valid/partial event")
    if any(error.stage == ProcessingStage.PREPROCESS and error.code in (
        "policy_invalid_skip", "policy_unsupported_skip", "policy_unusable_normalized_metadata",
    ) for error in event.errors):
        raise ValueError("Preprocessor policy blocks tracking")
    if not validate_packet(event.packet).tracking_eligible:
        raise ValueError("Raw event metadata is unsafe for tracking")
    normalized = event.normalized
    if not isinstance(normalized, dict):
        raise ValueError("Normalized event must be a dictionary")
    network, transport = normalized["network"], normalized["transport"]
    if not isinstance(network, dict) or not isinstance(transport, dict):
        raise ValueError("Normalized network/transport metadata is missing")
    if network["protocol"] != "IPv4":
        raise ValueError("Tracker currently supports only IPv4")
    protocol = FlowProtocol(transport["protocol"])

    def endpoint(ip, port):
        if not isinstance(ip, str) or len(ip) > 15:
            raise ValueError("Normalized IPv4 endpoint must be text")
        address = ip_address(ip)
        if address.version != 4 or str(address) != ip:
            raise ValueError("IP endpoint must be canonical IPv4")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Port endpoint must be an integer in 0..65535")
        return Endpoint(ip, port)

    src = endpoint(network["src_ip"], transport["src_port"])
    dst = endpoint(network["dst_ip"], transport["dst_port"])
    timestamp = normalized["timestamp"]
    if not isinstance(timestamp, str):
        raise ValueError("Normalized timestamp must be text")
    instant = datetime.fromisoformat(timestamp)
    if instant.utcoffset() is None or instant.utcoffset().total_seconds() != 0:
        raise ValueError("Normalized timestamp must be UTC with timezone")
    captured_length = normalized["captured_length"]
    if type(captured_length) is not int or captured_length < 0:
        raise ValueError("Normalized captured_length must be a nonnegative integer")
    if captured_length != event.packet.captured_length:
        raise ValueError("Normalized captured_length must match the raw packet")
    flags = ()
    if protocol == FlowProtocol.TCP:
        flags = transport["flags"]
        if not isinstance(flags, list) or any(not isinstance(flag, str) or flag not in TCP_FLAGS for flag in flags):
            raise ValueError("Normalized TCP flags must be a list of supported flag names")
    application = normalized.get("application")
    app_protocol = application.get("protocol") if isinstance(application, dict) else None
    if not isinstance(app_protocol, str) or app_protocol not in ("HTTP", "DNS", "SMTP", "MIME"):
        app_protocol = "UNKNOWN"
    return _TrackingInput(FlowKey(protocol, src, dst), src, dst, instant.astimezone(timezone.utc), app_protocol, captured_length, tuple(flags))


class SummaryCapacityError(ValueError):
    """Output must be drained before another summary can be retained."""


class TrackingCapacityError(ValueError):
    """Configured policy refuses a new flow while the table is full."""


class LateEventError(ValueError):
    """An old packet cannot recreate an already-expired lifetime."""


class FlowTracker:
    """Only one processing thread may mutate this tracker.

    A/B follow first observation. Maintenance clock never moves backwards;
    rejected/skipped events do not advance it. Terminal records remain resident
    until removal/expiry/reuse. Per-key generations retain stable lifetime IDs;
    their history is not bounded by max_active_flows.
    """

    def __init__(self, config: TrackerConfig | None = None) -> None:
        self.config = config if config is not None else TrackerConfig()
        if not isinstance(self.config, TrackerConfig):
            raise TypeError("FlowTracker config must be TrackerConfig")
        self._active_flows: dict[FlowKey, FlowRecord] = {}
        self._generations: dict[FlowKey, int] = {}
        self._tcp_handshakes: dict[FlowKey, TcpHandshake] = {}
        self._tcp_closes: dict[FlowKey, TcpClose] = {}
        self._completed_flows: list[FlowRecord] = []
        self._completed_meta: dict[str, dict] = {}
        self._watermark: datetime | None = None
        self._last_sweep: datetime | None = None

    @property
    def active_flows(self) -> dict[FlowKey, FlowRecord]:
        """Detached resident snapshots including terminal records awaiting expiry."""
        return deepcopy(self._active_flows)

    @property
    def active_count(self) -> int:
        return len(self._active_flows)

    @property
    def pending_count(self) -> int:
        return len(self._completed_flows)

    def export_flows(self) -> list[dict]:
        """Legacy inspection view: record fields for residents and pending lifetimes."""
        records = [*self._completed_flows, *self._active_flows.values()]
        return [record.to_dict() for record in sorted(records, key=lambda flow: flow.flow_id)]

    def pending_summary(self) -> dict | None:
        """Peek one detached summary; acknowledge only after a successful write."""
        if not self._completed_flows:
            return None
        flow = self._completed_flows[0]
        return {**flow.to_dict(), **deepcopy(self._completed_meta[flow.flow_id])}

    def acknowledge_summary(self, flow_id: str) -> None:
        if not self._completed_flows or self._completed_flows[0].flow_id != flow_id:
            raise ValueError("Only the first pending flow summary can be acknowledged")
        self._completed_flows.pop(0)
        self._completed_meta.pop(flow_id)

    def drain_completed_flows(self) -> list[dict]:
        """Legacy take-and-clear record snapshots; streaming callers should peek/ack."""
        records = [flow.to_dict() for flow in self._completed_flows]
        self._completed_flows.clear()
        self._completed_meta.clear()
        return records

    def remove_flow(self, key: FlowKey) -> FlowRecord | None:
        """Explicit detach; caller owns output. Generation history stays resident."""
        flow = self._active_flows.pop(key, None)
        self._tcp_handshakes.pop(key, None)
        self._tcp_closes.pop(key, None)
        return deepcopy(flow) if flow is not None else None

    def _now(self, value: datetime) -> datetime:
        instant = utc_time(value)
        return max(instant, self._watermark) if self._watermark is not None else instant

    def _require_space(self, additional: int) -> None:
        if self.pending_count + additional > self.config.max_pending_summaries:
            raise SummaryCapacityError("Pending summary queue is full; write and acknowledge summaries before retrying")

    def _completion(self, flow: FlowRecord, reason: str, now: datetime) -> tuple[FlowRecord, dict]:
        snapshot = deepcopy(flow)
        if reason in ("idle_timeout", "capacity_eviction") and snapshot.protocol == FlowProtocol.TCP:
            if snapshot.state not in (TcpState.CLOSED, TcpState.RESET):
                snapshot.state = TcpState.CLOSED
        metadata = {
            "schema_version": "1.0", "end_reason": reason,
            "end_time": now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "observed_state": flow.state,
        }
        return snapshot, metadata

    def _queue(self, completed: list[tuple[FlowRecord, dict]]) -> None:
        for flow, metadata in completed:
            self._completed_flows.append(flow)
            self._completed_meta[flow.flow_id] = metadata

    def expire(self, now: datetime) -> int:
        """Force a bounded sweep. Write/ack between batches until this returns 0."""
        instant = self._now(now)
        keys = sorted((key for key, flow in self._active_flows.items() if is_expired(flow, instant, self.config)),
                      key=lambda key: self._active_flows[key].flow_id)
        if keys:
            self._require_space(1)
            keys = keys[:self.config.max_pending_summaries - self.pending_count]
        completed = [self._completion(self._active_flows[key], "idle_timeout", instant) for key in keys]
        self._queue(completed)
        for key in keys:
            self.remove_flow(key)
        self._watermark = self._last_sweep = instant
        return len(keys)

    def finish(self, reason: str = "capture_eof", now: datetime | None = None) -> int:
        """Queue a bounded batch of resident summaries. Caller writes between batches.

        Capture termination preserves observed TCP state; it does not invent FIN.
        """
        if reason not in ("capture_eof", "capture_stopped", "capture_error"):
            raise ValueError("Unsupported capture completion reason")
        if not self._active_flows:
            return 0
        instant = self._now(now) if now is not None else self._watermark
        available = self.config.max_pending_summaries - self.pending_count
        self._require_space(1)
        keys = sorted(self._active_flows, key=lambda key: self._active_flows[key].flow_id)[:available]
        completed = [self._completion(self._active_flows[key], reason, instant) for key in keys]
        self._queue(completed)
        for key in keys:
            self.remove_flow(key)
        return len(keys)

    def track(self, event: ProcessedEvent) -> ProcessedEvent:
        if not isinstance(event, ProcessedEvent):
            raise TypeError("FlowTracker.track requires a ProcessedEvent")
        processed = deepcopy(event)
        processed.flow = None
        if processed.processing_action != ProcessingAction.TRACK:
            return processed
        processed.errors = [error for error in processed.errors if not (
            error.stage == ProcessingStage.TRACK and error.code.startswith("tracker_")
        )]
        try:
            data = _tracking_input(processed)
            key, src, dst = data.key, data.src, data.dst
            instant = self._now(data.timestamp)
            sweep = self._last_sweep is None or (instant - self._last_sweep).total_seconds() >= self.config.expiry_check_interval
            expired = {candidate for candidate, flow in self._active_flows.items()
                       if is_expired(flow, instant, self.config)} if sweep else set()
            # Never associate to an expired key just because the sweep is throttled.
            if key in self._active_flows and is_expired(self._active_flows[key], instant, self.config):
                expired.add(key)
            record = self._active_flows.get(key) if key not in expired else None
            reopen = (record is not None and key.protocol == FlowProtocol.TCP
                      and record.state in (TcpState.CLOSED, TcpState.RESET)
                      and "SYN" in data.flags and not set(data.flags) & {"ACK", "FIN", "RST"})
            if record is None and (instant - data.timestamp).total_seconds() >= idle_timeout(key.protocol, self.config):
                raise LateEventError("Packet is too old to create a flow at the current processing time")
            if record is None and self.active_count - len(expired) >= self.config.max_active_flows:
                # Expired flows take precedence over capacity policy, even between sweeps.
                expired = {candidate for candidate, flow in self._active_flows.items() if is_expired(flow, instant, self.config)}
                sweep = True
            removals = {candidate: "idle_timeout" for candidate in expired}
            if record is None and self.active_count - len(expired) >= self.config.max_active_flows:
                if self.config.capacity_policy == CapacityPolicy.SKIP_NEW:
                    raise TrackingCapacityError("Active flow table is full; configured policy skips new flows")
                oldest = min((candidate for candidate in self._active_flows if candidate not in expired),
                             key=lambda candidate: (self._active_flows[candidate].last_seen, self._active_flows[candidate].flow_id))
                removals[oldest] = "capacity_eviction"
            self._require_space(len(removals) + int(reopen))
            completed = [self._completion(self._active_flows[candidate], reason, instant)
                         for candidate, reason in sorted(removals.items(), key=lambda item: self._active_flows[item[0]].flow_id)]
            if reopen:
                completed.append(self._completion(record, "tcp_reuse", instant))
            is_new = record is None or reopen
            if is_new:
                generation = self._generations.get(key, 0) + 1
                record = FlowRecord(
                    flow_id=make_flow_id(key, generation), protocol=key.protocol,
                    endpoint_a=src, endpoint_b=dst, start_time=data.timestamp, last_seen=data.timestamp,
                    application_protocol=data.application,
                    state=TcpState.NEW if key.protocol == FlowProtocol.TCP else None,
                )
            direction = FlowDirection.FORWARD if (src, dst) == (record.endpoint_a, record.endpoint_b) else FlowDirection.BACKWARD
            updated = update_statistics(record, direction=direction, timestamp=data.timestamp,
                                        captured_length=data.captured_length, flags=data.flags, application_protocol=data.application)
            if key.protocol == FlowProtocol.TCP:
                state, handshake = update_handshake(record.state, TcpHandshake() if is_new else self._tcp_handshakes[key],
                                                    direction=direction, flags=data.flags)
                state, close = update_close(state, TcpClose() if is_new else self._tcp_closes[key],
                                           direction=direction, flags=data.flags)
                updated = replace(updated, state=state)
            processed.flow = updated.association(direction)
            # No mutations above this line: transition failures cannot partially expire/evict.
            self._queue(completed)
            for candidate in removals:
                self.remove_flow(candidate)
            self._active_flows[key] = updated
            if key.protocol == FlowProtocol.TCP:
                self._tcp_handshakes[key], self._tcp_closes[key] = handshake, close
            if is_new:
                self._generations[key] = generation
            self._watermark = instant
            if sweep:
                self._last_sweep = instant
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            code = "tracker_invalid_metadata"
            if isinstance(error, SummaryCapacityError):
                code = "tracker_summary_capacity"
            elif isinstance(error, TrackingCapacityError):
                code = "tracker_flow_capacity"
            elif isinstance(error, LateEventError):
                code = "tracker_late_event"
            processed.flow = None
            processed.processing_action = ProcessingAction.SKIP_TRACKING
            processed.errors.append(ProcessingError(ProcessingStage.TRACK, code, f"Cannot associate flow: {error}"))
        old_fragments = {part for error in event.errors for part in error.message.split("; ")}
        notes = [part for part in (event.reason or "").split("; ") if part and part not in old_fragments]
        processed.reason = "; ".join(dict.fromkeys(notes + [error.message for error in processed.errors])) or None
        return processed
