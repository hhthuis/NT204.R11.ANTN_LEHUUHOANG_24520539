from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


output_path = Path("TEST/malformed-packet.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

client_mac = "02:00:00:00:00:01"
server_mac = "02:00:00:00:00:02"

packets = [
    (
        Ether(src=client_mac, dst=server_mac, type=0x0800)
        / Raw(b"\x45\x00\x00\x14\x00\x01\x00\x00")
    ),
    (
        Ether(src=client_mac, dst=server_mac)
        / IP(src="10.0.0.11", dst="10.0.0.20", proto=6)
        / Raw(b"\x00\x50\x13\x88")
    ),
    (
        Ether(src=client_mac, dst=server_mac)
        / IP(src="10.0.0.12", dst="10.0.0.20")
        / TCP(sport=52000, dport=80, flags="PA", seq=1001)
        / Raw(b"GET / HTTP/1.1\r\nMalformed header\r\n\r\n")
    ),
    (
        Ether(src=client_mac, dst=server_mac)
        / IP(src="10.0.0.13", dst="10.0.0.25")
        / TCP(sport=52001, dport=25, flags="PA", seq=2001)
        / Raw(b"EHLO client.example.test")
    ),
]

wrpcap(str(output_path), packets)
print(f"Created {output_path} with {len(packets)} packets")
