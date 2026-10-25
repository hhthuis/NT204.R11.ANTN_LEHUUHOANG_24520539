"""Lab 3 data models, without rule parsing, role inference or matching.

Type annotations describe the contract. Text syntax/value validation belongs
to Parser & Validator; input validation and buffer creation belong to Adapter.
"""

import base64
from copy import deepcopy
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum, StrEnum
from typing import Any, Literal

from ids.flows.models import Endpoint, FlowDirection, FlowProtocol, FlowRecord
from ids.processing_models import ProcessedEvent


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii"), "length": len(value)}
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            raise ValueError("Engine timestamps must include a timezone")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, FlowRecord):
        return _json_value(value.to_dict())  # Includes the Lab 2 derived duration.
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _json_value(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


class JsonModel:
    __slots__ = ()

    def to_dict(self) -> dict[str, Any]:
        """Export detached JSON-compatible data; binary is Base64 plus length."""
        return _json_value(self)


class RuleStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


class MatchStatus(StrEnum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    SKIPPED = "SKIPPED"  # Required data unavailable; reason explains why.


@dataclass(frozen=True, slots=True)
class PortRange(JsonModel):
    start: int
    end: int  # Inclusive; equal bounds represent one port.


@dataclass(frozen=True, slots=True)
class RuleHeader(JsonModel):
    protocol: Literal["tcp", "udp", "ip", "any"]
    src_ip: str = "any"  # 'any', single IPv4 or IPv4 CIDR after validation.
    src_port: PortRange | None = None  # None means any port.
    direction: Literal["->", "<>"] = "->"
    dst_ip: str = "any"
    dst_port: PortRange | None = None
    action: Literal["alert"] = "alert"


@dataclass(frozen=True, slots=True)
class ContentCondition(JsonModel):
    pattern: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None
    buffer: str = "payload"


@dataclass(frozen=True, slots=True)
class FlowCondition(JsonModel):
    direction: Literal["to_server", "to_client"] | None = None
    established: bool | None = None  # Require established / not_established / neither.


@dataclass(frozen=True, slots=True)
class FlagsCondition(JsonModel):
    flags: tuple[str, ...]  # Names as in normalized TCP flags: SYN, ACK, ...
    mode: Literal["exact", "all", "any", "none"] = "exact"
    ignore: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SizeCondition(JsonModel):
    operator: Literal["=", "!", "<", "<=", ">", ">=", "<>", "<=>"]
    value: int
    upper: int | None = None


@dataclass(frozen=True, slots=True)
class Rule(JsonModel):
    header: RuleHeader
    sid: int
    rev: int
    msg: str
    contents: tuple[ContentCondition, ...] = ()  # Preserve declaration order.
    flow: FlowCondition | None = None
    flags: FlagsCondition | None = None
    dsize: SizeCondition | None = None
    classtype: str | None = None
    priority: int | None = None
    source_file: str | None = None
    source_line: int | None = None


@dataclass(slots=True)
class FlowContext(JsonModel):
    record: FlowRecord
    direction: FlowDirection
    established: bool | None = None  # None means unknown, not False.
    client: Endpoint | None = None
    server: Endpoint | None = None
    role_reason: str | None = None

    def __post_init__(self) -> None:
        self.record = deepcopy(self.record)


@dataclass(slots=True)
class EngineInput(JsonModel):
    event: ProcessedEvent
    flow: FlowContext | None = None
    buffers: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.event = deepcopy(self.event)
        self.flow = deepcopy(self.flow)
        self.buffers = deepcopy(self.buffers)


@dataclass(frozen=True, slots=True)
class ContentMatch(JsonModel):
    content_index: int
    buffer: str
    start: int
    end: int  # Exclusive byte position; not a character index.
    pattern: bytes


@dataclass(frozen=True, slots=True)
class MatchResult(JsonModel):
    sid: int
    rev: int
    status: MatchStatus
    contents: tuple[ContentMatch, ...] = ()
    checks: tuple[str, ...] = ()  # Successful header/flow/flags/dsize checks.
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionEvent(JsonModel):
    timestamp: datetime
    sid: int
    rev: int
    msg: str
    src: Endpoint
    dst: Endpoint
    protocol: FlowProtocol
    application_protocol: str
    flow_id: str | None
    match: MatchResult
    priority: int | None = None
    classtype: str | None = None
    packet_id: int | None = None
    schema_version: str = field(default="1.0", init=False)
