# T07 — TCP handshake

## Yêu cầu bài tập và mục đích

T07 trong bài tập 2: SYN → SYN/ACK → ACK phải thuộc một flow, kết thúc ở
ESTABLISHED. Kiểm tra packet không payload vẫn cập nhật state và counters;
association của packet trước giữ state tại thời điểm xử lý.

## Đầu vào và flow

PCAP tổng hợp bằng Scapy, Ethernet/IPv4/TCP, explicit MAC và timestamps UTC
microseconds. Không phải capture mạng thật; không cần root hoặc resolve MAC.

A=10.0.0.2:51000, B=10.0.0.1:8080. A là first-observed sender, khác endpoint
low khi sort key. Flow ID duy nhất:
flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2.

| Packet | Offset | Chiều | Flags | Seq | Ack | Payload | Bytes | State mong đợi | State thực tế |
|---|---:|---|---|---:|---:|---:|---:|---|---|
| 1 | 0.0s | forward A→B | SYN | 1000 | 0 | 0 | 54 | HANDSHAKE | HANDSHAKE |
| 2 | 0.1s | backward B→A | SYN/ACK | 5000 | 1001 | 0 | 54 | HANDSHAKE | HANDSHAKE |
| 3 | 0.2s | forward A→B | ACK | 1001 | 5001 | 0 | 54 | ESTABLISHED | ESTABLISHED |

Base time 2026-10-09T00:00:00Z. Sequence/ACK numbers tạo fixture TCP thông
thường; tracker nhận diện bằng flags/direction/thứ tự quan sát, chưa kiểm
tra tính đúng của sequence/ACK numbers.

Luồng kiểm thử: PcapReader → Parser → Decoder → Preprocessor → FlowTracker →
actual.jsonl và flows.json. Config lưu cùng case; timeout/capacity chưa thực
thi trong Task 13. main.py vẫn là CLI bài 1; dùng script reproduce cho bài 2.

## Kết quả mong đợi và thực tế

Expected là literal độc lập, không dùng tracker để sinh đáp án. So sánh exact
match associations và toàn bộ final FlowRecord. Cả ba events valid/track,
errors=[], reason=null; raw/decoded/normalized/status/errors giữ nguyên qua
tracker. Integration đọc lại JSONL/JSON và kiểm tra sequence/ACK fixture.

| Chỉ số | Mong đợi | Thực tế |
|---|---:|---:|
| Số flow | 1 | 1 |
| State cuối | ESTABLISHED | ESTABLISHED |
| packet_count / byte_count | 3 / 162 | 3 / 162 |
| forward_packet_count / forward_byte_count | 2 / 108 | 2 / 108 |
| backward_packet_count / backward_byte_count | 1 / 54 | 1 / 54 |
| syn_count / ack_count | 2 / 2 | 2 / 2 |
| fin_count / rst_count | 0 / 0 | 0 / 0 |
| duration | 0.2s | 0.2s |
| application_protocol | UNKNOWN | UNKNOWN |

SYN/ACK tăng cả SYN và ACK counters. Bytes là captured length gồm headers,
không payload bytes. Application UNKNOWN là phù hợp vì chỉ có control packets.

## Files và lệnh chạy

- input.pcap: ba packet đầu vào.
- config.toml: bản sao config dùng khi chạy.
- expected.json: associations và final record mong đợi.
- actual.jsonl: ba ProcessedEvent thực tế.
- flows.json: final record ESTABLISHED.
- result.txt: stdout/exit code script, integration và full suite thực tế.

```bash
./venv/bin/python -m tests.lab02.reproduce_t07
./venv/bin/python -m pytest tests/lab02/test_t07_tcp_handshake.py -v
./venv/bin/python -m pytest -q
```

Tái hiện ngoài repo: thêm --output-dir /tmp/ids-t07 vào lệnh reproduce.
Kết quả: T07 PASS, integration 1 passed, full suite 676 passed.

## Kiểm thử bổ sung và giới hạn

40 unit tests ở tests/lab02/test_tcp_handshake.py kiểm tra thiếu/sai chiều/sai
thứ tự, retransmissions, initiator backward, ACK+PSH/ECE, missing/invalid flags,
flows độc lập, UDP, skip/error, cleanup/new generation và atomic updates.
Chi tiết và log source commit: TEST/lab02/task13/.

T07 hoàn tất; T09 FIN/RST close, T10 DNS UDP và T12 timeout còn làm riêng.
Không xử lý TCP reassembly, simultaneous open, sequence/ACK-number validation,
TLS, tự đóng flow hoặc CLI bài 2 ở task này.
