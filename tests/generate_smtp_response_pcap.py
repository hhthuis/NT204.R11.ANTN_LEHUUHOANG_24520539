from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


output_path = Path("TEST/smtp-response.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

client_mac = "02:00:00:00:00:01"
server_mac = "02:00:00:00:00:02"
client_ip = "10.0.0.10"
server_ip = "10.0.0.25"
client_port = 51000
server_port = 25

payloads = [
    b"220 mail.example.test ESMTP ready\r\n",
    (
        b"250-mail.example.test\r\n"
        b"250-PIPELINING\r\n"
        b"250 STARTTLS\r\n"
    ),
    b"354 End data with <CR><LF>.<CR><LF>\r\n",
    b"550 5.1.1 Mailbox unavailable\r\n",
]

packets = []
sequence_number = 2001

for payload in payloads:
    packet = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="PA",
            seq=sequence_number,
            ack=1001,
        )
        / Raw(payload)
    )
    packets.append(packet)
    sequence_number += len(payload)

wrpcap(str(output_path), packets)
print(f"Created {output_path} with {len(packets)} packets")
