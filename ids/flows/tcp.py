"""Conservative handshake recognition from observed TCP flags and direction.

This is capture-order recognition, not TCP sequence/ACK-number validation,
stream reassembly or simultaneous-open handling. Close/reset comes separately.
"""

from dataclasses import dataclass, replace

from ids.flows.models import FlowDirection, TcpState
from ids.preprocessors.validation import TCP_FLAGS


@dataclass(frozen=True, slots=True)
class TcpHandshake:
    """Private per-lifetime evidence, independent of packet/flag counters."""

    initiator: FlowDirection | None = None
    syn_ack_seen: bool = False


def update_handshake(
    state: TcpState, context: TcpHandshake, *, direction: FlowDirection,
    flags: tuple[str, ...],
) -> tuple[TcpState, TcpHandshake]:
    """Return new state/evidence without changing either input.

    Need SYN, reverse SYN/ACK, then initiator ACK in observation order.
    Retransmissions do not regress evidence; FIN/RST never complete a handshake.
    Seeing only SYN/ACK marks HANDSHAKE but cannot substitute for a seen SYN.
    """
    state, direction = TcpState(state), FlowDirection(direction)
    if not isinstance(context, TcpHandshake):
        raise TypeError("Handshake context must be TcpHandshake")
    if not isinstance(flags, (tuple, list)) or any(
        not isinstance(flag, str) or flag not in TCP_FLAGS for flag in flags
    ):
        raise ValueError("Handshake requires supported TCP flag names")
    present = set(flags)
    if state in (TcpState.ESTABLISHED, TcpState.CLOSING, TcpState.CLOSED, TcpState.RESET):
        return state, context
    if present & {"FIN", "RST"}:
        return state, context
    if "SYN" in present:
        if "ACK" not in present:
            if context.initiator is None:
                context = replace(context, initiator=direction)
        elif context.initiator is not None and direction != context.initiator:
            context = replace(context, syn_ack_seen=True)
        return TcpState.HANDSHAKE, context
    if "ACK" in present and context.syn_ack_seen and direction == context.initiator:
        return TcpState.ESTABLISHED, context
    return state, context
