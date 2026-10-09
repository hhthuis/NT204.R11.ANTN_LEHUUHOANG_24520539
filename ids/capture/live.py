from collections.abc import Callable

from scapy.interfaces import get_if_list
from scapy.config import conf
from scapy.packet import Packet
from scapy.sendrecv import sniff


PacketHandler = Callable[[Packet], None]


def validate_interface(interface: str) -> None:
    if not interface.strip():
        raise ValueError("Network interface name cannot be empty")
    if interface not in get_if_list():
        raise ValueError(f"Network interface not found: {interface}")


def capture_live(
    interface: str,
    packet_handler: PacketHandler,
) -> None:
    """Capture packets from an interface and forward them immediately."""
    validate_interface(interface)

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
        )
    except KeyboardInterrupt:
        return


def capture_live_periodic(
    interface: str, packet_handler: PacketHandler, tick_handler: Callable[[], None], interval: float,
) -> None:
    """One persistent socket; packet callbacks and idle ticks share one thread.

    Socket remains open between bounded sniff sessions. chainCC lets the caller
    handle Ctrl+C and flush its pipeline; output/callback exceptions propagate.
    """
    validate_interface(interface)
    failure: Exception | None = None

    def handle(packet):
        nonlocal failure
        try:
            packet_handler(packet)
        except Exception as error:
            # Scapy catches callback exceptions as socket failures. Return from
            # prn, stop this session, then raise outside Scapy to preserve output errors.
            failure = error

    with conf.L2listen(iface=interface) as capture_socket:
        while True:
            sniff(opened_socket=capture_socket, prn=handle, store=False,
                  timeout=interval, chainCC=True, stop_filter=lambda packet: failure is not None)
            if failure is not None:
                raise failure
            tick_handler()
