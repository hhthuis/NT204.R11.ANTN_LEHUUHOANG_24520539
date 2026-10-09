"""Synthetic DNS wire packets shared by UDP tracking tests and T10 replay."""

from datetime import datetime, timezone
from decimal import Decimal

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, UDP, dns_compress

from ids.decoders.decoder import decode_event
from ids.models import CaptureSource
from ids.pipeline import parse_packet
from ids.preprocessors.preprocessor import preprocess_event


def make_dns_packet(
    *, response=False, transaction_id=0x1234, name="Example.Test.",
    client_ip="10.0.0.2", client_port=53000, server_ip="10.0.0.1", server_port=53,
    offset="0.0", payload=None, compressed=False,
):
    """Explicit MAC/UTC microseconds; payload override permits empty/unknown UDP.

    Serialize DNS into Raw so Parser receives actual DNS bytes, not model fields.
    A response carries one A answer; this fixture intentionally has no EDNS OPT.
    """
    if payload is None:
        message = DNS(
            id=transaction_id, qr=int(response), rd=1, aa=int(response), ra=int(response),
            qd=DNSQR(qname=name, qtype="A", qclass="IN"),
        )
        if response:
            message.an = DNSRR(rrname=name, type="A", rclass="IN", ttl=300, rdata="192.0.2.10")
        payload = bytes(dns_compress(message) if compressed else message)
    if response:
        src, sport, dst, dport = server_ip, server_port, client_ip, client_port
        source_mac, dest_mac = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, sport, dst, dport = client_ip, client_port, server_ip, server_port
        source_mac, dest_mac = "02:00:00:00:00:02", "02:00:00:00:00:01"
    packet = Ether(src=source_mac, dst=dest_mac) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if payload:
        packet /= Raw(payload)
    start = Decimal(str(datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()))
    packet.time = start + Decimal(offset)
    return packet


def prepare_packet(packet, packet_id=1):
    """Reload the serialized Ethernet frame, then run production processing."""
    wire_packet = Ether(bytes(packet))
    wire_packet.time = packet.time
    parsed = parse_packet(wire_packet, packet_id, CaptureSource("pcap", "udp-dns-unit.pcap"))
    return preprocess_event(decode_event(parsed))
