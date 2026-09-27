from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap


output_path = Path("TEST/unknown-protocol.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

client_mac = "02:00:00:00:00:01"
server_mac = "02:00:00:00:00:02"
server_ip = "10.0.0.20"

packets = [
    (
        Ether(src=client_mac, dst=server_mac)
        / IP(src="10.0.0.11", dst=server_ip)
        / TCP(sport=52000, dport=9999, flags="PA", seq=1001)
        / Raw(b"CUSTOM/1.0 hello\r\n")
    ),
    (
        Ether(src=client_mac, dst=server_mac)
        / IP(src="10.0.0.12", dst=server_ip)
        / UDP(sport=53000, dport=9999)
        / Raw(b"\x01\x02\x03\x04unknown udp payload\xff")
    ),
    (
        Ether(src=client_mac, dst=server_mac)
        / IP(src="10.0.0.13", dst=server_ip)
        / TCP(sport=52001, dport=80, flags="PA", seq=2001)
        / Raw(b"this is not an HTTP request\r\n")
    ),
]

wrpcap(str(output_path), packets)
print(f"Created {output_path} with {len(packets)} packets")
