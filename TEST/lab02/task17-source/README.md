# Task 17 — CLI pipeline, PCAP/live và writers

## Files

- ids/processing_pipeline.py: ProcessingPipeline parse→decode→preprocess→track,
  một tracker/phiên, event writer và flow writer. write_pending peek→write→ack,
  failure không ack. finish() bounded batches, không ghi trùng khi gọi lại.
- ids/cli.py: parser mặc định giữ bài1; processed mode có --config/--flows-output.
  load config và kiểm tra input/output collisions trước khi truncate. PCAP mở/
  validate trước writers; EOF/interrupt/error xuất flows với reason tương ứng.
- ids/capture/live.py: validate_interface và capture_live_periodic dùng một
  persistent L2 socket, sniff timeout theo expiry interval; packet callback và
  idle ticks chạy cùng thread. Socket vẫn mở giữa các sniff sessions; Ctrl+C
  propagate để CLI finish. Callback errors được raise ngoài Scapy để không bị
  thư viện nuốt như socket errors. Không dùng capture queue hoặc worker tracker.
- ids/output/jsonl.py: JsonlWriter nhận model to_dict hoặc summary dict, giữ
  kiểu ghi một object mỗi dòng; runtime output line-buffered UTF8. .gitignore
  output/ trước đây cũng ignore ids/output/; đã anchor /output/ và track writer
  cùng __init__ để repo clone chứa module cần import. Runtime output vẫn ignore.
- ids/config.py và ids/decoders/decoder.py: cập nhật mô tả đã nối processed CLI.

## API và semantics

run_processed_pcap/run_processed_live trả RunResult(packet_count,flow_count,
stopped). PCAP dùng event timestamps và Tracker sweep interval; EOF output
resident flows, giữ observed TCP state, end_reason=capture_eof. Valid event
summary overflow chưa commit → force expiry batches/write/ack rồi retry packet
chưa được count. Invalid/skipped packet vẫn output, không tiến clock.

Live dùng UTC idle ticks khi không có traffic; Ctrl+C dừng socket, finish theo
capture_stopped và exit0 khi output thành công. Capture failure finalize theo
capture_error rồi báo lỗi; startup/config/path/I/O/capture error exit2 ở CLI.
Lỗi output không báo thành công; không có transaction atomic giữa hai files.

Flow JSONL flat gồm record fields và schema_version/end_reason/end_time/
observed_state. EOF không ép ESTABLISHED thành CLOSED hoặc tăng FIN/RST; idle/
capacity có lifecycle CLOSED và observed_state để phân biệt state theo capture.
Pending queue có giới hạn; writer chỉ ack sau write thành công, không silent drop.

## Lệnh

```bash
./venv/bin/python main.py --mode processed --pcap TEST/lab02/T10/input.pcap \
  --config config/default.toml --output output/processed-events.jsonl \
  --flows-output output/flows.jsonl
sudo ./venv/bin/python main.py --mode processed --interface eth0 \
  --config config/default.toml --output output/live-events.jsonl \
  --flows-output output/live-flows.jsonl
```

Chọn đúng interface trên máy; live cần raw socket permissions. Lệnh parser
cũ không đổi. --config/--flows-output yêu cầu processed mode, tránh settings bị
ignore. Paths không trùng PCAP/config/output khác, kể cả symlink/hardlink.

## Kiểm thử

32 tests mới ở test_processed_cli.py, test_processing_pipeline.py và
 test_periodic_capture.py: config decoder/preprocessor/capacity, DNS/TCP state,
EOF/stop/error, empty/bad PCAP, path aliases/config lỗi trước output, old schema,
idle no-packet ticks, Ctrl+C/socket cleanup, callback/timer/write error,
summary batching/peek-ack/no duplication và skipped future timestamp.

Live tests mô phỏng socket/capture/clock, không capture network thật hoặc dùng
root. Full suite837 passed tại source validation; stdout/commands result.txt.
CLI subprocess replay các PCAP Lab2 có evidence riêng ở commit kế tiếp.

Remaining limitations: Packet-level parsing, không TCP/IP reassembly/TLS;
DNS binary generic text view có thể partial trong khi parse/tracking hợp lệ;
per-key generation history chưa bounded. Không thay thế feature extractor/
rule engine các bài tiếp theo. PCAP model-fixture T05/T06/T14 vẫn chạy API tests,
CLI chỉ nhận PCAP/interface, không thêm JSONL input reader ở task này.
