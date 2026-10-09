# T13 — Flow statistics

> Artifacts trong thư mục là snapshot Task 12 (TCP NEW). Từ Task 13,
> script/test dùng expected HANDSHAKE → HANDSHAKE → ESTABLISHED, còn counters,
> time, direction và IDs giữ nguyên. FIN/RST close chưa triển khai ở Task 13.
> Tái hiện phiên bản hiện tại ngoài repo để giữ log/artifacts lịch sử:
> `./venv/bin/python -m tests.lab02.reproduce_t13 --output-dir /tmp/ids-task13-t13`.
> Log regression hiện tại: `TEST/lab02/task13/result.txt`.

## Mục đích và nguồn input

Kiểm tra packet/byte/flag counters và duration khi có nhiều packet hai chiều.
PCAP sinh bằng Scapy, không phải traffic capture thật: 13 Ethernet/IPv4 packets,
gồm 9 TCP, 3 UDP cùng endpoint pair và 1 ICMP unsupported. Explicit MAC tránh
resolve MAC/raw socket. Decimal timestamps giữ microseconds và thứ tự đọc PCAP
có hai packet timestamp cũ hơn các packet đứng trước.

Luồng: PcapReader → Parser → Decoder → Preprocessor → FlowTracker → actual.jsonl
và flows.json. Config được lưu trong config.toml; Tracker timeout/capacity chưa
thực thi ở Task 12, không kiểm thử lifecycle ở case statistics này.

## Packet scenarios

A=10.0.0.2:51000, B=10.0.0.1:8080. Đây là orientation theo packet đầu tiên
quan sát được; packet timestamp sớm hơn từ B không đổi A/B.

| Packet | Protocol/flags | Direction | Offset giây | Captured bytes | Scenario |
|---|---|---|---:|---:|---|
| 1 | TCP SYN | forward | 2.0 | 54 | payload rỗng, UNKNOWN application |
| 2 | TCP SYN/ACK | backward | 2.1 | 54 | tăng cả SYN và ACK |
| 3 | TCP ACK | forward | 2.2 | 54 | payload rỗng vẫn tính packet/bytes |
| 4 | TCP PSH/ACK | forward | 2.3 | 97 | HTTP GET, payload 43 bytes, nâng app=HTTP |
| 5 | TCP PSH/ACK | backward | 2.4 | 120 | HTTP response, payload 66 bytes |
| 6 | TCP ACK | backward | 1.0 | 54 | timestamp cũ, start_time lùi nhưng last_seen không lùi |
| 7 | TCP PSH/ACK | forward | 2.45 | 97 | cùng payload/sequence với packet 4, retransmission vẫn tính |
| 8 | TCP FIN/ACK | forward | 2.5 | 54 | tăng FIN và ACK |
| 9 | TCP RST/ACK | backward | 2.6 | 54 | tăng RST và ACK |
| 10 | UDP | forward | 3.0 | 47 | payload hello 5 bytes, flow khác TCP |
| 11 | ICMP | skip | 99.0 | 42 | không tăng counters/time của flow |
| 12 | UDP | backward | 1.5 | 48 | reply! 6 bytes, timestamp cũ |
| 13 | UDP | forward | 3.5 | 42 | payload rỗng, tiếp tục sau ICMP |

## Expected và actual

| Field | TCP | UDP |
|---|---:|---:|
| packet_count | 9 | 3 |
| byte_count | 638 | 137 |
| forward_packet_count | 5 | 2 |
| forward_byte_count | 356 | 89 |
| backward_packet_count | 4 | 1 |
| backward_byte_count | 282 | 48 |
| SYN_count | 2 | 0 |
| ACK_count | 8 | 0 |
| FIN_count | 1 | 0 |
| RST_count | 1 | 0 |
| start_time offset | 1.0s | 1.5s |
| last_seen offset | 2.6s | 3.5s |
| duration | 1.6s | 2.0s |
| application_protocol | HTTP | UNKNOWN |

Times có base 2026-10-09T00:00:00Z, xuất UTC microsecond ISO. Tổng tracked=12
packet/775 byte; ICMP còn trong actual JSONL với status/reason và flow=null.
Bytes cộng captured lengths gồm Ethernet/IP/transport headers, không riêng
payload. TCP payload tổng 152 bytes nhưng TCP byte_count=638. Expected values
và IDs là literals từ fixture/spec, không chạy updater để sinh expected.

Thực tế: tất cả fields trong expected.json khớp actual; hai chiều/counters/time/
application đúng, raw/decoded/normalized/status/errors/reason không đổi qua
Tracker. Integration đọc lại JSONL/flow snapshots, kiểm tra captured sizes,
retransmission payload+sequence và totals bằng tổng captured lengths đầu vào.
Flow ID/direction không thay đổi khi gặp older timestamps hay HTTP nhận diện muộn.

## Files và tái hiện

- input.pcap: 13 packet đầu vào.
- config.toml: cấu hình đã dùng.
- expected.json: associations và toàn bộ final flow records mong đợi.
- actual.jsonl: 13 ProcessedEvent thực tế.
- flows.json: 2 final flow snapshots.
- result.txt: script PASS, integration 1 passed; full suite 635 passed.

```bash
./venv/bin/python -m tests.lab02.reproduce_t13
./venv/bin/python -m pytest tests/lab02/test_t13_flow_statistics.py -v
./venv/bin/python -m pytest -q
```

--output-dir /tmp/ids-t13 cho phép tái hiện ngoài repo.

## Phạm vi

TCP state vẫn NEW dù đã đếm FIN/RST, UDP state=null. Chưa state transitions,
automatic close/timeout/capacity, main CLI bài 2 hoặc TCP reassembly. T13 không
thay thế T07/T09 và UDP ở đây chưa phải DNS query/response của T10. Missing
flags/duplicate flags, skip/corrupt metadata, equal times/DST fold, first-known
label conflicts, snapshot preservation và updater atomicity có unit tests ở
tests/lab02/test_flow_statistics.py.
