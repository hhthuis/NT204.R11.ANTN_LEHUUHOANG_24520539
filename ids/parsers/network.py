from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from ids.models import NetworkInfo


class UnsupportedNetworkProtocol(Exception):
    pass


class MalformedNetworkPacket(ValueError):
    pass


def parse_ipv4(packet: Packet) -> NetworkInfo:
    if IP not in packet:
        if Ether in packet and int(packet[Ether].type) == 0x0800:
            raise MalformedNetworkPacket(
                "Ethernet frame declares IPv4 but its header is missing or truncated"
            )

        raise UnsupportedNetworkProtocol("Packet does not contain IPv4")

    ip = packet[IP]

    flags_text = str(ip.flags)
    flags = flags_text.split("+") if flags_text else []

    packet_length = (
        int(ip.len)
        if ip.len is not None
        else len(bytes(ip))
    )

    return NetworkInfo(
        protocol="IPv4",
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        ttl=int(ip.ttl),
        packet_length=packet_length,
        identification=int(ip.id),
        flags=flags,
        fragment_offset=int(ip.frag),
    )
