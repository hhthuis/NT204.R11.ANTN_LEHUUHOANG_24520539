"""Conservative handshake and close recognition from flags and direction.

This is capture-order recognition, not TCP sequence/ACK-number validation,
stream reassembly or simultaneous-open handling.
"""

from dataclasses import dataclass, replace

from ids.flows.models import FlowDirection, TcpState
from ids.preprocessors.validation import TCP_FLAGS


@dataclass(frozen=True, slots=True)
class TcpHandshake:
    """Private per-lifetime evidence, independent of packet/flag counters."""

    initiator: FlowDirection | None = None
    syn_ack_seen: bool = False


@dataclass(frozen=True, slots=True)
class TcpClose:
    """FIN and opposite-direction ACK evidence, separate from flag counters."""

    forward_fin: bool = False
    backward_fin: bool = False
    forward_fin_acked: bool = False
    backward_fin_acked: bool = False


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


def update_close(
    state: TcpState, context: TcpClose, *, direction: FlowDirection,
    flags: tuple[str, ...],
) -> tuple[TcpState, TcpClose]:
    """Recognize both FINs and their opposite ACKs, or an immediate reset.

    ACK can only acknowledge a previously observed opposite-direction FIN.
    FIN/ACK may both acknowledge the peer and close its own sending side.
    FIN retransmission preserves evidence; terminal states stay terminal.
    Sequence/ACK numbers are not validated, so these are logical capture states.
    """
    state, direction = TcpState(state), FlowDirection(direction)
    if not isinstance(context, TcpClose):
        raise TypeError("Close context must be TcpClose")
    if not isinstance(flags, (tuple, list)) or any(
        not isinstance(flag, str) or flag not in TCP_FLAGS for flag in flags
    ):
        raise ValueError("Close tracking requires supported TCP flag names")
    present = set(flags)
    if state in (TcpState.CLOSED, TcpState.RESET):
        return state, context
    if "RST" in present:
        return TcpState.RESET, context
    # A contradictory SYN+FIN or a stray SYN/ACK is not close evidence.
    if "SYN" in present:
        return state, context
    changes = {}
    if direction == FlowDirection.FORWARD:
        if "ACK" in present and context.backward_fin:
            changes["backward_fin_acked"] = True
        if "FIN" in present:
            changes["forward_fin"] = True
    else:
        if "ACK" in present and context.forward_fin:
            changes["forward_fin_acked"] = True
        if "FIN" in present:
            changes["backward_fin"] = True
    updated = replace(context, **changes)
    if updated.forward_fin and updated.backward_fin:
        if updated.forward_fin_acked and updated.backward_fin_acked:
            return TcpState.CLOSED, updated
    if updated.forward_fin or updated.backward_fin:
        return TcpState.CLOSING, updated
    return state, updated
