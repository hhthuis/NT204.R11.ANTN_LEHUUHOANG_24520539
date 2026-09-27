# Packet Capture & Parser for IDS

Module đọc packet từ file PCAP, phân tích IPv4, TCP, UDP, HTTP/1.x, DNS và
SMTP, sau đó chuyển mỗi packet thành một event chuẩn hóa và ghi ra file JSON
Lines. Cấu trúc event được thiết kế để các module IDS phía sau không cần truy
cập trực tiếp đối tượng packet của Scapy.

## Trạng thái hiện tại

Đã triển khai:

- Đọc lần lượt từng packet từ file PCAP bằng Scapy `PcapReader`.
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
- Hoàn thành 11/12 test case bắt buộc, từ TC-01 đến TC-11.
- Đánh dấu packet không hỗ trợ hoặc lỗi bằng `parse_status` và `errors`.

Chưa triển khai:

- Live capture từ network interface.
- TCP stream reassembly.
- Test case chính thức cho malformed packet.

## Yêu cầu môi trường

- Python 3.12 trở lên.
- Linux hoặc WSL được khuyến nghị.
- Quyền root hoặc Linux capabilities sẽ cần khi live capture được bổ sung.

Phiên bản đã dùng khi kiểm thử gần nhất ngày 27/09/2026:

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

## Pipeline xử lý

```text
PCAP file
    ↓
PcapReader
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

Live capture trong tương lai sẽ đưa packet vào cùng hàm `parse_packet()`.

## Cấu trúc project

```text
main.py                         Điểm khởi chạy chương trình
ids/
├── cli.py                     CLI và điều phối PCAP reader
├── models.py                  Cấu trúc PacketEvent
├── pipeline.py                Pipeline parse packet
├── capture/
│   ├── pcap.py                Đọc file PCAP
│   └── live.py                Chưa triển khai
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

Kết quả kiểm thử hiện tại:

```text
50 passed
```

Tiến độ test case bắt buộc: 11/12, tương đương khoảng 92%.

## Giới hạn hiện tại

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
- Parser làm việc trên từng packet và chưa ghép dữ liệu từ nhiều TCP segment.
- Chương trình mới hỗ trợ IPv4 với TCP hoặc UDP.

## Sử dụng AI

- Công cụ: OpenAI Codex.
- Mục đích: tư vấn kiến trúc, thiết kế cấu trúc event, hướng dẫn và hỗ trợ
  triển khai PCAP reader, IPv4/TCP/UDP parser, application protocol detector,
  pipeline, JSONL writer, kiểm thử tự động và tài liệu kiểm thử.
- Các phần có sử dụng hỗ trợ AI: `ids/models.py`, `ids/output/jsonl.py`,
  `ids/capture/pcap.py`, `ids/parsers/network.py`,
  `ids/parsers/transport.py`, `ids/parsers/application/detector.py`,
  `ids/parsers/application/http.py`, `ids/parsers/application/dns.py`,
  `ids/parsers/application/smtp.py`, `ids/pipeline.py`, `ids/cli.py`,
  `main.py`, các file trong `tests/` và tài liệu trong `TEST/`.
- Người thực hiện có trách nhiệm kiểm tra, chạy thử và hiểu mã nguồn trước khi
  nộp bài.

## Kế hoạch tiếp theo

1. Hoàn thành TC-12 malformed packet.
2. Thêm live capture dùng chung parsing pipeline.
