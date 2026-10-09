"""Flow contracts; no capture, protocol parsing, or tracking side effects."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class FlowProtocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"


class FlowDirection(StrEnum):
    FORWARD = "forward"
    BACKWARD = "backward"


class TcpState(StrEnum):
    NEW = "NEW"
    HANDSHAKE = "HANDSHAKE"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    RESET = "RESET"


@dataclass(frozen=True, slots=True, order=True)
class Endpoint:
    """An already validated and normalized IP address and port."""

    ip: str
    port: int


@dataclass(frozen=True, slots=True)
class FlowKey:
    """A hashable bidirectional key, independent of packet direction.

    Sorting is solely for lookup. A FlowRecord keeps A/B in the order first
    observed, so key order must not be used to infer client/server or direction.
    IP/protocol normalization belongs to the preprocessor.
    """

    protocol: FlowProtocol
    endpoint_low: Endpoint
    endpoint_high: Endpoint

    def __post_init__(self) -> None:
        low, high = sorted((self.endpoint_low, self.endpoint_high))
        object.__setattr__(self, "endpoint_low", low)
        object.__setattr__(self, "endpoint_high", high)


@dataclass(frozen=True, slots=True)
class FlowAssociation:
    """Immutable flow identity/direction/state at packet processing time."""

    flow_id: str
    direction: FlowDirection
    state: TcpState | None = None


@dataclass(slots=True)
class FlowRecord:
    """Mutable summary of one flow lifetime.

    A is the first observed sender; A -> B is forward. Byte counters sum
    PacketEvent.captured_length, including headers, rather than payload length.
    TCP tracking sets state explicitly; UDP state stays None. All times must be
    timezone-aware. Tracker/statistics maintain counters and UTC time bounds;
    these models do not consume packets or implement state transitions.
    """

    flow_id: str
    protocol: FlowProtocol
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    start_time: datetime
    last_seen: datetime
    application_protocol: str = "UNKNOWN"
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_packet_count: int = 0
    backward_byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: TcpState | None = None

    def __post_init__(self) -> None:
        for name in ("start_time", "last_seen"):
            if getattr(self, name).utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.last_seen.astimezone(timezone.utc) < self.start_time.astimezone(
            timezone.utc
        ):
            raise ValueError("last_seen cannot be earlier than start_time")

    @property
    def duration(self) -> float:
        """Elapsed seconds, derived so it cannot become a stale counter."""
        return (
            self.last_seen.astimezone(timezone.utc)
            - self.start_time.astimezone(timezone.utc)
        ).total_seconds()

    def association(self, direction: FlowDirection) -> FlowAssociation:
        """Capture a state snapshot without exposing this mutable record."""
        return FlowAssociation(
            flow_id=self.flow_id,
            direction=direction,
            state=self.state,
        )

    def to_dict(self) -> dict[str, Any]:
        """Export detached JSON-compatible data with UTC timestamps."""
        result = asdict(self)
        for name in ("start_time", "last_seen"):
            result[name] = (
                getattr(self, name)
                .astimezone(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
        result["duration"] = self.duration
        return result
