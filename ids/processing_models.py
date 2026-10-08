"""Data contracts for Lab 2 processing, independent of Scapy.

Decoded and normalized fields must contain JSON-compatible values. Keep binary
data in Base64 and preserve its original representation in ``packet``.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from ids.models import PacketEvent


class DecodeStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"


class PreprocessStatus(StrEnum):
    VALID = "valid"
    PARTIAL = "partial"
    INVALID = "invalid"


class ProcessingAction(StrEnum):
    TRACK = "track"
    SKIP_TRACKING = "skip_tracking"


class ProcessingStage(StrEnum):
    DECODE = "decode"
    PREPROCESS = "preprocess"
    TRACK = "track"


@dataclass(slots=True)
class ProcessingError:
    stage: ProcessingStage
    code: str
    message: str


@dataclass(slots=True)
class ProcessedEvent:
    """A packet snapshot with separate results from each processing stage.

    ``preprocess_status=None`` means validation has not run. Only the
    preprocessor may authorize tracking after checking the required fields.
    ``skip_tracking`` still permits logging the event and its reasons.
    The flow association will receive its dedicated model in the next task.
    """

    packet: PacketEvent
    schema_version: str = "1.0"
    decoded: dict[str, Any] = field(default_factory=dict)
    normalized: dict[str, Any] = field(default_factory=dict)
    decode_status: DecodeStatus = DecodeStatus.SKIPPED
    preprocess_status: PreprocessStatus | None = None
    processing_action: ProcessingAction = ProcessingAction.SKIP_TRACKING
    reason: str | None = None
    flow: dict[str, Any] | None = None
    errors: list[ProcessingError] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Processing must not mutate the caller's raw event or nested fields.
        self.packet = deepcopy(self.packet)

    def to_dict(self) -> dict[str, Any]:
        """Return detached data for JSON serialization; enums are strings."""
        return asdict(self)
