"""Bidirectional flow identity, direction and statistics; state/expiry come later."""

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address

from ids.flows.models import Endpoint, FlowDirection, FlowKey, FlowProtocol, FlowRecord, TcpState
from ids.flows.statistics import update_statistics
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


class FlowTracker:
    """Single-stream mutable tracker; callers receive detached event/table views.

    A is the first observed sender, not a key sort order or a client/server guess.
    Every accepted call counts one observation; retransmissions are not removed.
    Timeout/capacity and TCP state transitions are intentionally not implemented.
    """

    def __init__(self) -> None:
        self._active_flows: dict[FlowKey, FlowRecord] = {}
        self._generations: dict[FlowKey, int] = {}

    @property
    def active_flows(self) -> dict[FlowKey, FlowRecord]:
        """Inspection snapshot: caller changes cannot corrupt tracker identity."""
        return deepcopy(self._active_flows)

    def export_flows(self) -> list[dict]:
        """Detached snapshots with current statistics and UTC time bounds."""
        return [record.to_dict() for record in sorted(self._active_flows.values(), key=lambda flow: flow.flow_id)]

    def remove_flow(self, key: FlowKey) -> FlowRecord | None:
        """Explicit detach for future close/expiry; this does not infer TCP close."""
        flow = self._active_flows.pop(key, None)
        return deepcopy(flow) if flow is not None else None

    def track(self, event: ProcessedEvent) -> ProcessedEvent:
        """Attach identity/direction and update statistics without mutating caller.

        Only Preprocessor can authorize tracking. A skipped event never touches
        the table. Malformed normalized metadata is diagnosed before insertion.
        This API accepts ProcessedEvent; other object types are programming errors.
        """
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
            record = self._active_flows.get(key)
            is_new = record is None
            if record is None:
                generation = self._generations.get(key, 0) + 1
                record = FlowRecord(
                    flow_id=make_flow_id(key, generation), protocol=key.protocol,
                    endpoint_a=src, endpoint_b=dst, start_time=data.timestamp, last_seen=data.timestamp,
                    application_protocol=data.application,
                    state=TcpState.NEW if key.protocol == FlowProtocol.TCP else None,
                )
            direction = FlowDirection.FORWARD if (src, dst) == (record.endpoint_a, record.endpoint_b) else FlowDirection.BACKWARD
            updated = update_statistics(
                record, direction=direction, timestamp=data.timestamp,
                captured_length=data.captured_length, flags=data.flags, application_protocol=data.application,
            )
            processed.flow = updated.association(direction)
            self._active_flows[key] = updated
            if is_new:
                self._generations[key] = generation
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            processed.processing_action = ProcessingAction.SKIP_TRACKING
            processed.errors.append(ProcessingError(
                ProcessingStage.TRACK, "tracker_invalid_metadata", f"Cannot associate flow: {error}",
            ))
        old_fragments = {part for error in event.errors for part in error.message.split("; ")}
        notes = [part for part in (event.reason or "").split("; ") if part and part not in old_fragments]
        processed.reason = "; ".join(dict.fromkeys(notes + [error.message for error in processed.errors])) or None
        return processed
