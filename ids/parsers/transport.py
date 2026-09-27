from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from ids.models import TransportInfo


class UnsupportedTransportProtocol(Exception):
    pass


class MalformedTransportPacket(ValueError):
    pass


@dataclass(slots=True)
class TransportParseResult:
    info: TransportInfo
    payload: bytes


TCP_FLAG_NAMES = {
    0x001: "FIN",
    0x002: "SYN",
    0x004: "RST",
    0x008: "PSH",
    0x010: "ACK",
    0x020: "URG",
    0x040: "ECE",
    0x080: "CWR",
    0x100: "NS",
}


def decode_tcp_flags(value: int) -> list[str]:
    return [
        name
        for bit, name in TCP_FLAG_NAMES.items()
        if value & bit
    ]


def parse_transport(packet: Packet) -> TransportParseResult:
    if TCP in packet:
        tcp = packet[TCP]
        payload = bytes(tcp.payload)

        header_length = (
            int(tcp.dataofs) * 4
            if tcp.dataofs is not None
            else None
        )

        info = TransportInfo(
            protocol="TCP",
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            fields={
                "sequence_number": int(tcp.seq),
                "acknowledgment_number": int(tcp.ack),
                "flags": decode_tcp_flags(int(tcp.flags)),
                "window_size": int(tcp.window),
                "header_length": header_length,
                "checksum": (
                    int(tcp.chksum)
                    if tcp.chksum is not None
                    else None
                ),
            },
        )

        return TransportParseResult(
            info=info,
            payload=payload,
        )

    if UDP in packet:
        udp = packet[UDP]
        payload = bytes(udp.payload)

        info = TransportInfo(
            protocol="UDP",
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            fields={
                "length": (
                    int(udp.len)
                    if udp.len is not None
                    else 8 + len(payload)
                ),
                "checksum": (
                    int(udp.chksum)
                    if udp.chksum is not None
                    else None
                ),
            },
        )

        return TransportParseResult(
            info=info,
            payload=payload,
        )

    if IP in packet:
        protocol_number = int(packet[IP].proto)

        if protocol_number == 6:
            raise MalformedTransportPacket(
                "IPv4 packet declares TCP but its header is missing or truncated"
            )

        if protocol_number == 17:
            raise MalformedTransportPacket(
                "IPv4 packet declares UDP but its header is missing or truncated"
            )

    raise UnsupportedTransportProtocol(
        "IPv4 packet does not contain TCP or UDP"
    )
