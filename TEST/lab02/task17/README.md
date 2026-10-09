# Task 17 — Kiểm thử CLI tích hợp bài 2

Ngày kiểm thử: 09/10/2026.

## Mục tiêu và luồng chạy

```text
main.py --mode processed
  → CLI đọc config và kiểm tra đường dẫn
  → PCAP reader / live capture
  → parse_packet (bài 1)
  → decode_event → preprocess_event → FlowTracker
  → events.jsonl: mỗi packet một ProcessedEvent
  → flows.jsonl: mỗi vòng đời flow một summary khi được xuất
```

CLI mặc định `--mode parser` giữ schema PacketEvent của bài 1. Để chạy đầy đủ
bài 2 phải dùng `--mode processed`. `--config` đọc TOML; `--flows-output` chọn
file summary riêng với `--output` chứa events.

## Kết quả thực tế

Script gọi **main.py bằng subprocess**, chạy 13 PCAP có sẵn. PCAP nguồn được
tham chiếu trong `cases.json`, kèm SHA-256; không sinh lại hoặc sửa input cũ.
Mỗi thư mục `cli/<case>/` chứa config thực dùng, events.jsonl và flows.jsonl.

| Case / input dưới TEST/lab02/ | Events | Được tracking | Flow summaries |
|---|---:|---:|---:|
| T01/input.pcap | 5 | 4 | 1 |
| T02/input.pcap | 11 | 11 | 1 |
| T03/input.pcap | 14 | 14 | 1 |
| T04/input.pcap | 2 | 2 | 1 |
| http-form/input.pcap | 7 | 7 | 1 |
| T07/input.pcap | 3 | 3 | 1 |
| T08/input.pcap | 5 | 5 | 1 |
| T09/fin/input.pcap | 7 | 7 | 1 |
| T09/rst/input.pcap | 4 | 4 | 1 |
| T10/input.pcap | 2 | 2 | 1 |
| T11/input.pcap | 16 | 15 | 6 |
| T12/input.pcap | 4 | 4 | 3 |
| T13/input.pcap | 13 | 12 | 2 |
| **Tổng** | **93** | **90** | **21** |

Tất cả subprocess exit 0. Ba event skip vẫn được ghi và có reason; chúng không
đóng góp vào counters của flows. T01 có URI percent-escape lỗi bị policy skip;
T11/T13 có packet transport không hỗ trợ. Một flow có thể chứa nhiều event
thuộc các application message khác nhau.

Các kiểm tra chung trước khi báo PASS:

- Số lượng/thứ tự event và raw PacketEvent trùng kết quả parser của PCAP.
- Event skip có flow=null và reason; event track có flow association.
- Tập flow ID của summaries khớp các association, không summary trùng trong
  từng lần chạy. Mỗi observation được chấp nhận đóng góp đúng một lần.
- Tổng packet/byte và counters hai chiều khớp events; byte tính captured_length,
  gồm header. IP/port chiều gửi/nhận khớp endpoint A/B.
- start_time/last_seen/duration khớp các timestamp quan sát; end_time không
  trước last_seen. SYN/ACK/FIN/RST counters khớp flags trong packet.
- Kiểm tra literal thêm cho URL decode, form lặp và dấu +, handshake,
  FIN/CLOSED, RST/RESET, DNS/UDP hai chiều và timeout tạo vòng đời mới.

Flow ID có phạm vi một tracker/phiên. Không gộp các file flows của nhiều phiên
theo riêng flow_id: cùng endpoint và generation trong các phiên khác nhau có
thể tạo cùng ID.

### T12: thời gian PCAP và thao tác maintenance

CLI PCAP không đợi theo thời gian thực. Sweep chạy khi có packet, dùng timestamp
của packet. Trong replay T12, packet cuối ở giây 4.1 làm hai flow cũ hết hạn;
EOF xuất flow UDP mới, nên ba summaries có end_time ở giây 4.1. Hai flow cũ
có end_reason=idle_timeout; flow mới là capture_eof.

Test T12 chính thức tại ../T12/ gọi maintenance riêng ở giây 2, 4 và 6.1 khi
không có packet. Vì vậy end_time và reason của summary cuối khác replay CLI;
hai kiểm thử dùng lịch maintenance khác nhau. Live CLI có tick định kỳ để
expire flow kể cả khi không có traffic.

## Đọc kết quả

Ví dụ DNS hai chiều: [events](cli/T10/events.jsonl), [flows](cli/T10/flows.jsonl).

Trong events.jsonl:

- `packet`: raw event, URI/body/payload gốc.
- `decoded`: biểu diễn đã decode; `normalized`: dữ liệu chuẩn hóa an toàn.
- `decode_status`, `preprocess_status`, `processing_action`, `reason`, `errors`:
  kết quả xử lý và quyết định có cho tracking hay không.
- `flow`: flow_id, direction và snapshot state ở thời điểm packet.

Trong flows.jsonl:

- Endpoint A/B, protocol, application_protocol, packet/byte counters tổng và
  hai chiều, SYN/ACK/FIN/RST, start_time/last_seen/duration và state.
- `schema_version`, `end_reason`, `end_time`, `observed_state`: metadata xuất.
  EOF không tự biến ESTABLISHED thành CLOSED hoặc tạo FIN/RST giả.
  Timeout/capacity có thể đóng lifecycle TCP; observed_state giữ state quan sát.

## Chạy lại

```bash
./venv/bin/python main.py --mode processed \
  --pcap TEST/lab02/T10/input.pcap --config config/default.toml \
  --output output/processed-events.jsonl --flows-output output/flows.jsonl

./venv/bin/python -m tests.lab02.reproduce_task17_cli
./venv/bin/python -m pytest tests/lab02/test_task17_cli_replay.py -v -s
./venv/bin/python -m pytest -q
```

Script có `--output-dir /tmp/ids-task17` để giữ nguyên bằng chứng trong repo.
Lệnh main.py ghi đè các output được chỉ định; CLI chặn output trùng input,
config hoặc output còn lại, bao gồm symlink/hardlink.

## Phạm vi xác minh

- Kiểm thử CLI subprocess mới: **1 passed**, gồm 13 lần chạy.
- Kiểm thử source Task 17: **32 passed**, lưu ở ../task17-source/.
- Toàn bộ suite hiện tại: **838 passed**, gồm các formal case T01–T14.
- Kiểm tra bản Git archive sạch của commit source e04d198: **837 passed**;
  phép kiểm tra này diễn ra trước khi thêm test subprocess thứ 838.
- T05/T06/T14 dùng model JSONL fixtures qua API tests để tạo trường thiếu/sai
  mà packet parser không sinh ra. Chúng không chạy qua CLI PCAP trong bảng trên.
- Live tests mô phỏng socket/capture/clock: periodic tick, Ctrl+C, socket cleanup,
  callback/I/O/capture error. Chưa thu traffic thật trong Task 17 này.

[cases.json](cases.json) lưu paths, config source, input hash, số lượng và stdout/
stderr/exit code từng CLI. [result.txt](result.txt) lưu kết quả subprocess,
pytest mới, toàn bộ suite và kiểm tra checkout sạch.

## Giới hạn

Parser làm việc theo packet, chưa TCP stream/IP fragment reassembly hoặc TLS.
DNS payload nhị phân có thể khiến generic UTF-8 view partial dù DNS parsing/
tracking hợp lệ. Active table/pending summaries có giới hạn, nhưng lịch sử
generation theo key chưa có giới hạn tổng bộ nhớ. Hai file output chưa có
transaction atomic; write lỗi không được báo thành công. Pending flow summary
chỉ được acknowledge sau khi writer ghi thành công.
