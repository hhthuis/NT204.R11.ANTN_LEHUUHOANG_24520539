import argparse
from pathlib import Path

from scapy.packet import Packet

from ids.capture.live import capture_live
from ids.capture.pcap import read_pcap
from ids.models import CaptureSource
from ids.output.jsonl import JsonlWriter
from ids.pipeline import parse_packet


def process_packet(
    packet: Packet,
    packet_id: int,
    source: CaptureSource,
    writer: JsonlWriter,
) -> None:
    event = parse_packet(
        packet=packet,
        packet_id=packet_id,
        source=source,
    )
    writer.write(event)


def run_pcap(
    input_path: str | Path,
    output_path: str | Path,
) -> int:
    input_path = Path(input_path)

    source = CaptureSource(
        type="pcap",
        name=input_path.name,
    )

    packet_count = 0

    with JsonlWriter(output_path) as writer:
        for packet_count, packet in enumerate(
            read_pcap(input_path),
            start=1,
        ):
            process_packet(
                packet=packet,
                packet_id=packet_count,
                source=source,
                writer=writer,
            )

    return packet_count


def run_live(
    interface: str,
    output_path: str | Path,
) -> int:
    source = CaptureSource(
        type="interface",
        name=interface,
    )

    packet_count = 0

    with JsonlWriter(output_path) as writer:
        def handle_packet(packet: Packet) -> None:
            nonlocal packet_count

            packet_count += 1
            process_packet(
                packet=packet,
                packet_id=packet_count,
                source=source,
                writer=writer,
            )

        capture_live(
            interface=interface,
            packet_handler=handle_packet,
        )

    return packet_count


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Packet Capture and Parser for IDS"
    )

    source_group = parser.add_mutually_exclusive_group(required=True)

    source_group.add_argument(
        "--pcap",
        help="Path to input PCAP file",
    )

    source_group.add_argument(
        "--interface",
        help="Network interface for live capture",
    )

    parser.add_argument(
        "--output",
        default="output/events.jsonl",
        help="Path to output JSONL file",
    )

    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        if args.pcap is not None:
            packet_count = run_pcap(
                input_path=args.pcap,
                output_path=args.output,
            )
        else:
            packet_count = run_live(
                interface=args.interface,
                output_path=args.output,
            )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(
        f"Processed {packet_count} packets. "
        f"Output: {args.output}"
    )

    return 0
