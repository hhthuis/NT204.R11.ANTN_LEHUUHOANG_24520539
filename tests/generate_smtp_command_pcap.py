from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


output_path = Path("TEST/smtp-command.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

client_mac = "02:00:00:00:00:01"
server_mac = "02:00:00:00:00:02"
client_ip = "10.0.0.10"
server_ip = "10.0.0.25"
client_port = 51000
server_port = 2526

payloads = [
    b"HELO legacy.example.test\r\n",
    b"EHLO client.example.test\r\n",
    b"MAIL FROM:<alice@example.test> SIZE=123\r\n",
    b"RCPT TO:<bob@example.test>\r\n",
]

packets = []
sequence_number = 1001

for payload in payloads:
    packet = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="PA",
            seq=sequence_number,
            ack=2001,
        )
        / Raw(payload)
    )
    packets.append(packet)
    sequence_number += len(payload)

wrpcap(str(output_path), packets)
print(f"Created {output_path} with {len(packets)} packets")
