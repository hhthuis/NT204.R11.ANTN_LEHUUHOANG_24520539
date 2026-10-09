# T10 — DNS UDP query/response

## Yêu cầu và mục đích

T10 trong bài tập 2 yêu cầu DNS UDP hai chiều thuộc một UDP flow, packet/byte
counts đúng. PCAP tổng hợp có một query A và một response A, qua đầy đủ Parser
→ Decoder → Preprocessor → FlowTracker; output gồm ProcessedEvent JSONL và
final flow summary. Không tự gán DNS fields để bỏ qua parsing.

Input sinh bằng Scapy, Ethernet/IPv4/UDP, explicit MAC và UTC Decimal timestamps
microseconds. Không phải traffic capture thật; không cần root/raw socket.
main.py vẫn là CLI bài 1, dùng script reproduce cho pipeline bài 2.

## Input và từng packet

A=10.0.0.2:53000, B=10.0.0.1:53. A là first-observed sender; B là resolver.
Transaction ID=0x1234 (4660), query Example.Test. type A, class IN.
Response NOERROR có một answer A=192.0.2.10, TTL=300, cùng transaction ID.
DNS messages không có EDNS OPT; answer name uncompressed trong formal PCAP.

| Packet | Offset | Endpoint | Kind | Payload bytes | Captured bytes | Expected direction/state | Actual direction/state |
|---|---:|---|---|---:|---:|---|---|
| 1 | 0.0s | A→B | query | 30 | 72 | forward/null | forward/null |
| 2 | 0.2s | B→A | response | 58 | 100 | backward/null | backward/null |

Base time 2026-10-09T00:00:00Z. Captured length gồm Ethernet14 + IPv4 20 + UDP8
+ DNS payload. Domain wire có trailing dot; parser tạo raw PacketEvent name
Example.Test (đã bỏ trailing dot); Preprocessor tạo normalized name example.test
và giữ raw PacketEvent/payload Base64 nguyên vẹn. Type A/class IN, answer address
192.0.2.10 và TTL300 được xác nhận ở cả raw/normalized views.

## Expected và actual

| Field | Mong đợi | Thực tế |
|---|---|---|
| Số flow | 1 | 1 |
| protocol / application_protocol | UDP / DNS | UDP / DNS |
| state | null | null |
| packet_count / byte_count | 2 / 172 | 2 / 172 |
| forward_packet_count / forward_byte_count | 1 / 72 | 1 / 72 |
| backward_packet_count / backward_byte_count | 1 / 100 | 1 / 100 |
| syn_count / ack_count / fin_count / rst_count | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| start_time | 2026-10-09T00:00:00.000000Z | khớp |
| last_seen | 2026-10-09T00:00:00.200000Z | khớp |
| duration | 0.2s | 0.2s |

Flow ID duy nhất:
flow-b9c4049d557c4aef63cdf8b3c0ba566852aa046982c9b92773f21373c6c45efa.
ID dựa trên UDP bidirectional tuple và generation, không DNS transaction ID.
IDs hiện không có global capture namespace, chỉ so sánh trong cùng tracker/
replay lifetime. UDP không có TCP state/handshake/close transitions.

Expected associations, flow counters/time, DNS fields và diagnostics là literal
values từ fixture/spec, không lấy actual tracker output để sinh đáp án. Script
so sánh exact-match các projections này và full final FlowRecord. Integration
đọc lại JSONL/JSON, đối chiếu payload Base64 với DNS bytes từ PCAP, captured
lengths, directional sums và parsed question/answer/transaction ID/counts.
Harness xác nhận tracker không sửa raw/decoded/normalized/status/errors/reason
hoặc caller. Hai events preprocess_status=valid và processing_action=track.

## Chẩn đoán decoder — có partial nhưng không phải DNS malformed

| Packet | parse_status | decode_status | preprocess_status | action | Processing errors |
|---|---|---|---|---|---|
| Query | ok | ok | valid | track | [] |
| Response | ok | partial | valid | track | stage=decode, invalid_character_sequence |

DNS response là binary message. Parser đọc DNS đúng (packet.errors=[],
message_complete=true); generic text decoder hiện vẫn thử UTF-8 nên gặp byte
không hợp lệ tại bytes2:3. Reason trong response:
Invalid utf-8 sequence at bytes 2:3: invalid start byte.

Character view có replacement U+FFFD; raw Base64 vẫn khớp PCAP và parsed DNS
fields đúng. Preprocessor metadata hợp lệ nên tracker vẫn gắn UDP flow; tracker
không xóa chẩn đoán. expected.json có diagnostics riêng để partial không bị
che giấu hoặc bị coi nhầm là parse/tracking thất bại. Task này giữ decoder
policy hiện có, không triển khai DNS character decoding mới.

## Files và tái hiện

- input.pcap: hai UDP DNS packets, 72/100 captured bytes.
- config.toml: bản sao default config dùng khi chạy.
- expected.json: events/flows/DNS views/diagnostics mong đợi.
- actual.jsonl: hai ProcessedEvent thực tế.
- flows.json: một final UDP/DNS flow.
- result.txt: stdout và exit code thực tế của script, integration và full suite.

```bash
./venv/bin/python -m tests.lab02.reproduce_t10
./venv/bin/python -m pytest tests/lab02/test_t10_udp_dns.py -v
./venv/bin/python -m pytest -q
```

Thêm --output-dir /tmp/ids-t10 để tái hiện ngoài repo.
Kết quả: T10 PASS, integration 1 passed; full suite 772 passed.

## Kiểm thử bổ sung và phạm vi

19 tests Task 15 ở tests/lab02/test_udp_dns_flow.py: multiple transaction IDs,
retransmission, changed domain, changed endpoint/port, response first,
TCP/UDP separation, empty/unknown→DNS, DNS name compression (response88 bytes),
normalization, preserved binary diagnostics, skipped/bad metadata và updater
atomicity. API/rules/regression log T07/T08/T09/T11/T13: TEST/lab02/task15/.

T10 hoàn tất; mandatory còn T12 idle timeout. Chưa timeout/capacity/queue limit
(Task16), main CLI bài 2 (Task17), DNS transaction correlation hoặc fragment
reassembly. Không khẳng định mọi DNS resource-record variant hỗ trợ từ fixture
A không EDNS này; không phải kiểm thử traffic capture thật.
