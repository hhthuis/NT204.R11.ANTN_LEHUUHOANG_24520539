"""UTC clock and protocol-specific idle rules, independent of output/capture."""

from datetime import datetime, timezone

from ids.config import TrackerConfig
from ids.flows.models import FlowProtocol, FlowRecord


def utc_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("Flow maintenance time must be timezone-aware")
    return value.astimezone(timezone.utc)


def idle_timeout(protocol: FlowProtocol, config: TrackerConfig) -> float:
    return config.tcp_idle_timeout if protocol == FlowProtocol.TCP else config.udp_idle_timeout


def is_expired(flow: FlowRecord, now: datetime, config: TrackerConfig) -> bool:
    return (now - flow.last_seen.astimezone(timezone.utc)).total_seconds() >= idle_timeout(flow.protocol, config)
