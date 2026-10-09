import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path

from scapy.packet import Packet
from scapy.error import Scapy_Exception

from ids.capture.live import capture_live, capture_live_periodic, validate_interface
from ids.capture.pcap import read_pcap
from ids.config import ProcessingConfig, load_config
from ids.models import CaptureSource
from ids.output.jsonl import JsonlWriter
from ids.pipeline import parse_packet
from ids.processing_pipeline import ProcessingPipeline


@dataclass(frozen=True, slots=True)
class RunResult:
    packet_count: int
    flow_count: int
    stopped: bool = False


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_output_paths(inputs, outputs) -> None:
    """Reject aliases, symlinks and existing hard links before truncating output."""
    inputs = [Path(path) for path in inputs if path is not None]
    outputs = [Path(path) for path in outputs]
    for index, output in enumerate(outputs):
        if output.is_dir():
            raise ValueError(f"Output path is a directory: {output}")
        for other in inputs + outputs[:index]:
            if output.resolve() == other.resolve() or (output.exists() and other.exists() and output.samefile(other)):
                raise ValueError(f"Output paths must be distinct from inputs and each other: {output}")


def run_processed_pcap(input_path, output_path, flows_path, config: ProcessingConfig | None = None) -> RunResult:
    validate_output_paths([input_path], [output_path, flows_path])
    packets = read_pcap(input_path)
    # Open/validate the PCAP before touching either output, retaining one packet.
    try:
        first = next(packets, None)
        with JsonlWriter(output_path) as events, JsonlWriter(flows_path) as flows:
            pipeline = ProcessingPipeline(config or ProcessingConfig(), events, flows)
            stopped = False
            try:
                for packet in chain([first] if first is not None else [], packets):
                    pipeline.process(packet, CaptureSource("pcap", Path(input_path).name))
            except KeyboardInterrupt:
                stopped = True
            except Exception:
                pipeline.finish("capture_error")
                raise
            pipeline.finish("capture_stopped" if stopped else "capture_eof")
            return RunResult(pipeline.packet_count, pipeline.flow_count, stopped)
    finally:
        packets.close()


def run_processed_live(interface, output_path, flows_path, config: ProcessingConfig | None = None) -> RunResult:
    validate_interface(interface)
    validate_output_paths([], [output_path, flows_path])
    config = config or ProcessingConfig()
    with JsonlWriter(output_path) as events, JsonlWriter(flows_path) as flows:
        pipeline = ProcessingPipeline(config, events, flows)
        stopped = False
        try:
            capture_live_periodic(
                interface=interface,
                packet_handler=lambda packet: pipeline.process(packet, CaptureSource("interface", interface)),
                tick_handler=lambda: pipeline.expire(utc_now()),
                interval=config.tracker.expiry_check_interval,
            )
        except KeyboardInterrupt:
            stopped = True
        except Exception:
            pipeline.finish("capture_error", utc_now())
            raise
        pipeline.finish("capture_stopped", utc_now())
        return RunResult(pipeline.packet_count, pipeline.flow_count, stopped)


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
        description="IDS packet parser and Decoder/Preprocessor/FlowTracker pipeline"
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
    parser.add_argument("--mode", choices=("parser", "processed"), default="parser", help="parser: Lab 1; processed: full Lab 2 pipeline")
    parser.add_argument("--config", help="Optional TOML overrides for processed mode")
    parser.add_argument("--flows-output", help="Flow summary JSONL in processed mode (default: output/flows.jsonl)")

    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        if args.mode == "processed":
            config = load_config(args.config)
            flows_path = args.flows_output or "output/flows.jsonl"
            validate_output_paths([args.pcap, args.config], [args.output, flows_path])
            if args.pcap is not None:
                result = run_processed_pcap(args.pcap, args.output, flows_path, config)
            else:
                result = run_processed_live(args.interface, args.output, flows_path, config)
            print(f"Processed {result.packet_count} packets, wrote {result.flow_count} flow summaries. "
                  f"Events: {args.output}. Flows: {flows_path}")
            return 0
        if args.config is not None or args.flows_output is not None:
            raise ValueError("--config and --flows-output require --mode processed")
        validate_output_paths([args.pcap], [args.output])
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
    except (OSError, ValueError, Scapy_Exception) as error:
        parser.error(str(error))

    print(
        f"Processed {packet_count} packets. "
        f"Output: {args.output}"
    )

    return 0
