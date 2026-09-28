from collections.abc import Callable

from scapy.interfaces import get_if_list
from scapy.packet import Packet
from scapy.sendrecv import sniff


PacketHandler = Callable[[Packet], None]


def capture_live(
    interface: str,
    packet_handler: PacketHandler,
) -> None:
    """Capture packets from an interface and forward them immediately."""
    if not interface.strip():
        raise ValueError("Network interface name cannot be empty")

    if interface not in get_if_list():
        raise ValueError(f"Network interface not found: {interface}")

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
        )
    except KeyboardInterrupt:
        return
