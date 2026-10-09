# Packet Capture & Parser for IDS

Module bắt packet trực tiếp từ network interface hoặc đọc packet từ file PCAP,
phân tích IPv4, TCP, UDP, HTTP/1.x, DNS và SMTP, sau đó chuyển mỗi packet thành
một event chuẩn hóa và ghi ra file JSON Lines. Cấu trúc event được thiết kế để
các module IDS phía sau không cần truy cập trực tiếp đối tượng packet của Scapy.

## Trạng thái hiện tại

Đã triển khai:

- Đọc lần lượt từng packet từ file PCAP bằng Scapy `PcapReader`.
- Bắt packet trực tiếp từ network interface bằng Scapy `sniff`.
- Chuyển từng live packet ngay vào parsing pipeline và không lưu toàn bộ packet
  trong bộ nhớ.
- CLI yêu cầu chọn đúng một nguồn bằng `--pcap` hoặc `--interface`.
- PCAP và live capture sử dụng chung `parse_packet()` và `JsonlWriter`.
- Parse IPv4, TCP và UDP.
- Nhận diện HTTP, DNS và SMTP từ payload kết hợp thông tin transport/port.
- Nhận diện HTTP request và SMTP command trên port không chuẩn.
- Nhận diện DNS/UDP và DNS/TCP có length prefix.
- Parse HTTP request và response.
- Trích xuất HTTP method, target, version, status code, reason phrase,
  headers và body.
- Kiểm tra độ đầy đủ của HTTP body bằng Content-Length.
- Parse DNS query và response trên UDP hoặc TCP.
- Trích xuất DNS transaction ID, opcode, response code, flags, questions,
  answers, authority và additional records.
- Kiểm tra số lượng DNS record thực tế với các count trong header.
- Parse SMTP command và response.
- Trích xuất `HELO`, `EHLO`, `MAIL FROM`, `RCPT TO`, domain, mailbox và các
  tham số mở rộng của command.
- Trích xuất SMTP status code, message và multiline response.
- Hỗ trợ nhiều SMTP command hoặc response trong cùng một TCP payload.
- Ghi nhận timestamp của packet.
- Lưu payload dưới dạng Base64 và text preview.
- Chuẩn hóa dữ liệu bằng `PacketEvent`.
- Ghi mỗi event thành một dòng JSON.
- Hoàn thành đầy đủ 12/12 test case bắt buộc.
- Đánh dấu packet không hỗ trợ hoặc lỗi bằng `parse_status` và `errors`.

Chưa triển khai:

- TCP stream reassembly.

### Bài tập 2 — Model kết quả xử lý (Task 01)

- `ids/processing_models.py` định nghĩa `ProcessedEvent`, trạng thái decode,
  preprocess, action và lỗi xử lý theo stage/code/message.
- `packet` là bản sao sâu của `PacketEvent` gốc; `decoded` và `normalized`
  lưu kết quả riêng, không ghi đè raw URI/body/payload.
- Event mới có `decode_status="skipped"`, `preprocess_status=null` (chưa
  validation) và `processing_action="skip_tracking"`. Bỏ qua tracking vẫn
  cho phép ghi log event và nguyên nhân.
- Field đơn chưa có giá trị dùng `null`, danh sách dùng `[]`. Các dictionary
  `decoded`/`normalized` chỉ chứa dữ liệu tương thích JSON; byte dùng Base64.
- `flow=null` khi chưa tracking; sau Task 02 dùng model `FlowAssociation`.
- Model này chưa được nối vào CLI; Decoder, Preprocessor và Flow Tracker sẽ
  được triển khai ở các task tiếp theo.
- Kiểm tra hợp đồng dữ liệu bằng:
  `./venv/bin/python -m pytest tests/lab02/test_processing_models.py -v`.
  Đây là test nền tảng cho model, chưa phải các case T01–T14 của bài tập 2.
- Kết quả kiểm thử ngày 09/10/2026: 4 model tests passed, toàn bộ suite
  66 passed. Tài liệu và log tại `TEST/lab02/task01/`.

### Bài tập 2 — Model flow (Task 02)

- `ids/flows/models.py` định nghĩa `Endpoint`, `FlowKey`, `FlowRecord` và
  `FlowAssociation`, cùng enum protocol, direction và TCP state.
- `FlowKey` sắp xếp hai endpoint để tra cứu hai chiều, nhưng endpoint A/B trong
  `FlowRecord` giữ thứ tự quan sát: A là sender đầu tiên, A→B là forward.
- `FlowRecord` có đủ định danh, endpoint, thời gian, packet/byte counters tổng
  và hai chiều, SYN/ACK/FIN/RST counters và state theo yêu cầu bài 2.
- `byte_count` tính tổng `PacketEvent.captured_length`, gồm header; `duration`
  được tính từ hai timestamp có timezone, xuất timestamp dưới dạng UTC.
- UDP dùng `state=null`; TCP tracker sẽ cập nhật các trạng thái NEW,
  HANDSHAKE, ESTABLISHED, CLOSING, CLOSED, RESET ở task sau.
- `FlowAssociation` bất biến giữ flow ID, direction và state tại thời điểm
  xử lý packet; cập nhật `FlowRecord` không sửa state của event trước đó.
- Chưa có tạo flow ID, active table, tự cập nhật counters/state hay timeout.
  Test model không thay thế các case tracking T07–T13.
- Chạy: `./venv/bin/python -m pytest tests/lab02/test_flow_models.py -v`.
- Kết quả kiểm thử ngày 09/10/2026: 9 flow model tests mới; 13 model tests
  bài 2 passed và toàn bộ suite 75 passed.
- Tài liệu và log kiểm thử tại `TEST/lab02/task02/`.

### Bài tập 2 — Cấu hình xử lý (Task 03)

- `ids/config.py` định nghĩa config bất biến cho decoder/preprocessor/tracker,
  đọc TOML bằng thư viện chuẩn `tomllib` và báo lỗi bằng `ConfigError`.
- `config/default.toml` chứa charset ASCII/UTF-8, policy byte lỗi, giới hạn
  decode input/output, policy event invalid/unsupported, timeout TCP/UDP,
  chu kỳ kiểm tra expiry, giới hạn active flow và policy khi đầy bảng.
- Mặc định của dự án: decode input/output tối đa 1 MiB mỗi giá trị;
  TCP timeout 180 giây, UDP timeout 30 giây, kiểm tra expiry mỗi 1 giây,
  tối đa 10000 active flow. Đây là lựa chọn triển khai, không phải số do đề quy định.
- `load_config()` dùng mặc định trong code; `load_config(path)` đọc file và
  cho phép ghi đè một phần, giữ mặc định cho setting chưa có.
- Từ chối giá trị sai, timeout không hữu hạn, boolean thay số, policy không hỗ
  trợ và key viết nhầm. File lỗi/không tồn tại không âm thầm fallback.
- Các policy được mô tả trong file TOML và `TEST/lab02/task03/README.md`.
  Chưa nối cấu hình vào CLI hoặc thực thi decode/preprocess/track ở task này.
- Chạy test: `./venv/bin/python -m pytest tests/lab02/test_config.py -v`.
- Kết quả ngày 09/10/2026: 42 config tests passed, toàn bộ suite 117 passed.
  Tài liệu và log tại `TEST/lab02/task03/`.
- Hoàn thành giai đoạn 1 của bài 2: model kết quả xử lý, model flow và cấu hình.
  Bước tiếp theo: triển khai Decoder.

Ví dụ đọc cấu hình trong Python:

```python
from ids.config import load_config

config = load_config("config/default.toml")
print(config.tracker.tcp_idle_timeout)  # 180.0
```

### Bài tập 2 — Character decoder (Task 04)

- `ids/decoders/text.py` decode ASCII/UTF-8, trả text/charset/status/errors và
  sử dụng policy, giới hạn input/output của `DecoderConfig`.
- `ids/decoders/decoder.py` đọc payload Base64 đầy đủ từ `PacketEvent`, giữ
  raw packet và trả `ProcessedEvent` với `decoded.payload.text/charset/status`.
  Không dùng preview 256 byte làm nguồn decode.
- Byte lỗi: replace trả text có U+FFFD và status partial; strict trả error và
  text null. Charset sai/Base64 lỗi/raw thiếu được ghi nhận an toàn.
- Vượt giới hạn trả skipped/error theo policy, giữ raw và ghi reason. Output
  limit tính theo UTF-8 bytes trước JSON escaping, gồm expansion do replacement.
- Test: `./venv/bin/python -m pytest tests/lab02/test_decoder_text.py -v`.
- Kết quả ngày 09/10/2026: 25 test mới passed, toàn bộ suite 142 passed.
  Tài liệu/log tại `TEST/lab02/task04/`.
- Chưa có HTTP URL/form/HTML/MIME decoding hoặc nối character decoder vào CLI;
  các phần đó triển khai sau. T04 có bằng chứng và commit riêng.

## Yêu cầu môi trường

- Python 3.12 trở lên.
- Linux hoặc WSL được khuyến nghị.
- Live capture cần quyền root hoặc Linux capabilities để truy cập raw socket.

Phiên bản đã dùng khi kiểm thử gần nhất ngày 28/09/2026:

- Python 3.12.3.
- Scapy 2.7.0.
- pytest 9.1.1.

## Cài đặt

```bash
python -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Sử dụng

Chương trình yêu cầu chọn đúng một trong hai nguồn packet: file PCAP hoặc network
interface.

### Đọc file PCAP

Đọc một file PCAP và ghi kết quả ra JSONL:

```bash
python main.py \
  --pcap path/to/input.pcap \
  --output output/events.jsonl
```

Ví dụ với dữ liệu kiểm thử transport:

```bash
python -m tests.generate_transport_pcap

python main.py \
  --pcap TEST/transport-test.pcap \
  --output TEST/transport-test.jsonl
```

Kết quả mong đợi:

```text
Created TEST/transport-test.pcap with 5 packets
Processed 5 packets. Output: TEST/transport-test.jsonl
```

### Live capture

Xem danh sách interface có trên máy:

```bash
ip link show
```

Hoặc lấy danh sách interface Scapy có thể sử dụng:

```bash
python - <<'PY'
from scapy.interfaces import get_if_list
print(get_if_list())
PY
```

Bắt packet trực tiếp từ `eth0` và ghi kết quả ra JSONL:

```bash
sudo ./venv/bin/python main.py \
  --interface eth0 \
  --output output/live-events.jsonl
```

Mỗi packet được chuyển ngay vào pipeline và ghi thành một dòng JSON. Nhấn
`Ctrl+C` để dừng capture; chương trình sẽ đóng file output và in tổng số packet
đã xử lý.

Không truyền đồng thời `--pcap` và `--interface`. CLI sẽ báo lỗi nếu thiếu cả hai
nguồn hoặc nếu cả hai cùng xuất hiện.

## Pipeline xử lý

```text
PCAP file ──→ PcapReader ──┐
                           ├──→ process_packet()
Interface ──→ sniff ───────┘
                                  ↓
                            parse_packet()
                                  ↓
IPv4 parser
    ↓
TCP/UDP parser
    ↓
Application protocol detector
    ├── HTTP parser
    ├── DNS parser
    ├── SMTP parser
    └── UNKNOWN
    ↓
PacketEvent
    ↓
JSONL writer
```

Hai nguồn cùng gọi `parse_packet()` nên không có parser riêng cho live traffic và
PCAP.

## Cấu trúc project

```text
main.py                         Điểm khởi chạy chương trình
ids/
├── cli.py                     CLI và điều phối PCAP/live capture
├── models.py                  Cấu trúc PacketEvent
├── pipeline.py                Pipeline parse packet
├── capture/
│   ├── pcap.py                Đọc file PCAP
│   └── live.py                Bắt packet từ network interface
├── parsers/
│   ├── network.py             IPv4 parser
│   ├── transport.py           TCP/UDP parser
│   └── application/
│       ├── detector.py        Nhận diện HTTP, DNS và SMTP
│       ├── http.py            HTTP/1.x request/response parser
│       ├── dns.py             DNS query/response parser
│       └── smtp.py            SMTP command/response parser
└── output/
    └── jsonl.py               JSON Lines writer
tests/                         Kiểm thử tự động và script sinh PCAP
TEST/                          PCAP, JSONL, log và tài liệu kiểm thử
```

## Cấu trúc event

Mỗi dòng trong output là một JSON object. Ví dụ rút gọn:

```json
{
  "schema_version": "1.0",
  "packet_id": 1,
  "timestamp": "2026-09-17T00:00:00.000000Z",
  "source": {
    "type": "pcap",
    "name": "transport-test.pcap"
  },
  "network": {
    "protocol": "IPv4",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2"
  },
  "transport": {
    "protocol": "TCP",
    "src_port": 51000,
    "dst_port": 8080,
    "fields": {
      "flags": ["SYN"],
      "sequence_number": 1000
    }
  },
  "application": {
    "protocol": "UNKNOWN",
    "kind": null,
    "fields": {}
  },
  "parse_status": "ok",
  "errors": []
}
```

## Kiểm thử

Chạy toàn bộ test:

```bash
python -m pytest -v
```

Chạy từng test case transport:

```bash
python -m pytest -v tests/test_pcap_pipeline.py::test_tcp_handshake
python -m pytest -v tests/test_pcap_pipeline.py::test_tcp_data
python -m pytest -v tests/test_pcap_pipeline.py::test_udp_data
```

Chạy test cho application protocol detector:

```bash
python -m pytest -v tests/test_application_detector.py
```

Chạy các test HTTP bắt buộc:

```bash
python -m pytest -v tests/test_http_get.py
python -m pytest -v tests/test_http_post.py
python -m pytest -v tests/test_http_response.py
```

Chạy các test DNS bắt buộc:

```bash
python -m pytest -v tests/test_dns_query.py
python -m pytest -v tests/test_dns_response.py
```

Chạy các test SMTP hiện có:

```bash
python -m pytest -v tests/test_smtp_parser.py
python -m pytest -v tests/test_smtp_command.py
python -m pytest -v tests/test_smtp_response.py
```

Chạy test unknown protocol:

```bash
python -m pytest -v tests/test_unknown_protocol.py
```

Chạy test malformed packet:

```bash
python -m pytest -v tests/test_malformed_packet.py
```

Chạy test live capture adapter và live pipeline:

```bash
python -m pytest -v tests/test_live_capture.py
python -m pytest -v tests/test_live_pipeline.py
```

Các test live capture tự động mock Scapy `sniff`, vì vậy không cần quyền root,
không phụ thuộc interface của máy chạy test và vẫn kiểm tra packet được chuyển
vào pipeline chung rồi ghi ra JSONL.

Tài liệu và log kết quả:

- [TCP handshake](TEST/tcp-handshake.md)
- [TCP data](TEST/tcp-data.md)
- [UDP data](TEST/udp.md)
- [PCAP đầu vào](TEST/transport-test.pcap)
- [JSONL đầu ra](TEST/transport-test.jsonl)
- [HTTP GET](TEST/http-get.md)
- [HTTP POST](TEST/http-post.md)
- [HTTP response](TEST/http-response.md)
- [DNS query](TEST/dns-query.md)
- [DNS response](TEST/dns-response.md)
- [SMTP command](TEST/smtp-command.md)
- [SMTP response](TEST/smtp-response.md)
- [Unknown protocol](TEST/unknown-protocol.md)
- [Malformed packet](TEST/malformed-packet.md)

TC-09 SMTP command có đầy đủ artifact:

- [PCAP đầu vào](TEST/smtp-command.pcap)
- [JSONL đầu ra](TEST/smtp-command.jsonl)
- [Log kiểm thử](TEST/smtp-command-result.txt)

TC-10 SMTP response có đầy đủ artifact:

- [PCAP đầu vào](TEST/smtp-response.pcap)
- [JSONL đầu ra](TEST/smtp-response.jsonl)
- [Log kiểm thử](TEST/smtp-response-result.txt)

TC-11 unknown protocol có đầy đủ artifact:

- [PCAP đầu vào](TEST/unknown-protocol.pcap)
- [JSONL đầu ra](TEST/unknown-protocol.jsonl)
- [Log kiểm thử](TEST/unknown-protocol-result.txt)

TC-12 malformed packet có đầy đủ artifact:

- [PCAP đầu vào](TEST/malformed-packet.pcap)
- [JSONL đầu ra](TEST/malformed-packet.jsonl)
- [Log kiểm thử](TEST/malformed-packet-result.txt)

Kết quả kiểm thử hiện tại:

```text
62 passed
```

Tiến độ test case bắt buộc: 12/12, đạt 100%.

## Giới hạn hiện tại

- Live capture đã có automated test bằng packet giả lập, nhưng chưa lưu artifact
  của một phiên capture thủ công trên network interface thật trong `TEST/`.
- PCAP kiểm thử transport được tạo bằng Scapy, chưa phải capture từ traffic
  thực tế.
- HTTP parser xử lý một message nằm trọn trong một TCP packet; chưa ghép HTTP
  message bị chia trên nhiều TCP segment.
- Chưa giải mã `Transfer-Encoding: chunked`; body chunked hiện được giữ ở
  dạng raw body.
- Header trùng tên được nối bằng dấu phẩy trong output chuẩn hóa.
- DNS response bắt buộc hiện được kiểm thử với bản ghi `A`; parser lưu được
  các resource record khác dưới dạng dữ liệu JSON an toàn nhưng chưa có test
  riêng cho từng loại record.
- SMTP command và response hiện được kiểm thử bằng PCAP sinh bởi Scapy;
  chưa có capture SMTP từ lưu lượng thực tế.
- Malformed packet test sử dụng các frame bị cắt và payload lỗi được tạo có
  chủ đích bằng Scapy; chưa kiểm thử với PCAP hỏng thu từ môi trường thật.
- Parser làm việc trên từng packet và chưa ghép dữ liệu từ nhiều TCP segment.
- Chương trình mới hỗ trợ IPv4 với TCP hoặc UDP.

## Sử dụng AI

- Công cụ: OpenAI Codex.
- Mục đích: tư vấn kiến trúc, thiết kế cấu trúc event, hướng dẫn và hỗ trợ
  triển khai PCAP reader, live capture, IPv4/TCP/UDP parser, application protocol
  detector, pipeline, JSONL writer, kiểm thử tự động và tài liệu kiểm thử.
- Các phần có sử dụng hỗ trợ AI: `ids/models.py`, `ids/output/jsonl.py`,
  `ids/processing_models.py`, `tests/lab02/test_processing_models.py`,
  `ids/flows/models.py`, `tests/lab02/test_flow_models.py`,
  `ids/config.py`, `config/default.toml`, `tests/lab02/test_config.py`,
  `ids/decoders/text.py`, `ids/decoders/decoder.py`,
  `tests/lab02/test_decoder_text.py`,
  `ids/capture/pcap.py`, `ids/capture/live.py`, `ids/parsers/network.py`,
  `ids/parsers/transport.py`, `ids/parsers/application/detector.py`,
  `ids/parsers/application/http.py`, `ids/parsers/application/dns.py`,
  `ids/parsers/application/smtp.py`, `ids/pipeline.py`, `ids/cli.py`,
  `main.py`, các file trong `tests/` và tài liệu trong `TEST/`.
- Người thực hiện có trách nhiệm kiểm tra, chạy thử và hiểu mã nguồn trước khi
  nộp bài.

## Kế hoạch tiếp theo

1. Chạy live capture trên interface thật và lưu JSONL, log cùng tài liệu kiểm thử
   trong `TEST/`.
2. Kiểm thử parser với PCAP thu từ traffic thực tế.
3. Nghiên cứu TCP stream reassembly cho application message qua nhiều segment.
