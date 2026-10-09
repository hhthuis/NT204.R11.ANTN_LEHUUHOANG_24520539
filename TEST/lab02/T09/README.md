# T09 — TCP close: FIN và RST

## Yêu cầu và mục đích

T09 trong bài tập 2 yêu cầu flow chuyển CLOSED/RESET phù hợp khi gặp FIN/ACK
hoặc RST. Kiểm thử hai capture độc lập: handshake rồi đóng bình thường bằng
FIN, và handshake rồi reset bằng RST. Tất cả packet không payload vẫn được
xử lý state/counters, mỗi capture chỉ có một flow ID.

Input là PCAP tổng hợp bằng Scapy, Ethernet/IPv4/TCP; explicit MAC tránh
resolve MAC/raw socket, Decimal timestamps giữ microseconds. Không phải traffic
capture thật, không cần root. Luồng script: PcapReader → Parser → Decoder →
Preprocessor → FlowTracker → actual.jsonl và flows.json. main.py vẫn là bài 1.

A=10.0.0.2:51000, B=10.0.0.1:8080; A là first-observed sender. Cả hai capture
bắt đầu tracker riêng nên ID giống nhau:
flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2.
ID không phải global capture/session ID; hai capture độc lập không được tự
động gộp theo ID nếu thiếu nguồn capture/session bên ngoài.

## Case FIN — đóng hai chiều

Base time 2026-10-09T00:00:00Z. Payload=0 và captured_length=54 ở tất cả packet.

| Packet | Offset | Chiều | Flags | Seq | Ack | Mong đợi | Thực tế | Ý nghĩa |
|---|---:|---|---|---:|---:|---|---|---|
| 1 | 0.0s | forward | SYN | 1000 | 0 | HANDSHAKE | HANDSHAKE | bắt đầu handshake |
| 2 | 0.1s | backward | SYN/ACK | 5000 | 1001 | HANDSHAKE | HANDSHAKE | peer trả lời |
| 3 | 0.2s | forward | ACK | 1001 | 5001 | ESTABLISHED | ESTABLISHED | hoàn tất handshake |
| 4 | 0.3s | forward | FIN/ACK | 1001 | 5001 | CLOSING | CLOSING | A kết thúc chiều gửi |
| 5 | 0.4s | backward | ACK | 5001 | 1002 | CLOSING | CLOSING | B ACK FIN của A |
| 6 | 0.5s | backward | FIN/ACK | 5001 | 1002 | CLOSING | CLOSING | B kết thúc chiều gửi |
| 7 | 0.6s | forward | ACK | 1002 | 5002 | CLOSED | CLOSED | A ACK FIN của B |

Một FIN chưa đóng toàn bộ flow. Cần FIN của cả hai chiều và ACK xác nhận tương
ứng. Packet 5 chỉ xác nhận A đã kết thúc chiều gửi; B còn có thể gửi data cho
tới FIN của B. Context nhớ từng chiều, không suy đoán CLOSED từ fin_count=2.

## Case RST — ngắt ngay

| Packet | Offset | Chiều | Flags | Seq | Ack | Mong đợi | Thực tế |
|---|---:|---|---|---:|---:|---|---|
| 1 | 0.0s | forward | SYN | 1000 | 0 | HANDSHAKE | HANDSHAKE |
| 2 | 0.1s | backward | SYN/ACK | 5000 | 1001 | HANDSHAKE | HANDSHAKE |
| 3 | 0.2s | forward | ACK | 1001 | 5001 | ESTABLISHED | ESTABLISHED |
| 4 | 0.3s | backward | RST/ACK | 5001 | 1001 | RESET | RESET |

RST ngắt flow ngay, không cần FIN hoặc ACK sau đó. Payload=0, bytes=54 mỗi
packet. RST/ACK tăng cả RST và ACK counters.

## Final flow: expected và actual

Các ô dưới đều exact-match giữa expected.json và flows.json.

| Chỉ số | FIN expected = actual | RST expected = actual |
|---|---:|---:|
| Số flow | 1 | 1 |
| State cuối | CLOSED | RESET |
| packet_count / byte_count | 7 / 378 | 4 / 216 |
| forward_packet_count / forward_byte_count | 4 / 216 | 2 / 108 |
| backward_packet_count / backward_byte_count | 3 / 162 | 2 / 108 |
| syn_count / ack_count | 2 / 6 | 2 / 3 |
| fin_count / rst_count | 2 / 0 | 0 / 1 |
| duration | 0.6s | 0.3s |
| application_protocol | UNKNOWN | UNKNOWN |

start_time=2026-10-09T00:00:00.000000Z; last_seen FIN=00:00:00.600000Z,
RST=00:00:00.300000Z. Bytes là captured lengths gồm headers, không payload.
Expected states/directions/counters/time là literals độc lập, không chạy
production updater để sinh đáp án.

Mọi event valid/track, errors=[], reason=null. Harness kiểm tra raw PacketEvent,
decoded, normalized, status/errors/reason không đổi qua tracker; caller không
bị sửa. Integration đọc lại JSONL/JSON, kiểm tra sequence/ACK fixture, TCP flags,
state/direction/ID, toàn bộ final record và tổng bytes/packet hai chiều.

## Files và lệnh chạy

Mỗi thư mục fin/ và rst/ chứa:

- input.pcap: input của case (7 hoặc 4 packets).
- config.toml: bản sao config dùng khi chạy.
- expected.json: associations và final flow mong đợi.
- actual.jsonl: 7 hoặc 4 ProcessedEvent thực tế.
- flows.json: một final flow CLOSED hoặc RESET.

README.md và result.txt nằm chung ở T09/. Log lưu stdout/exit code thực tế cho
script reproduce, hai integration tests và toàn bộ suite.

```bash
./venv/bin/python -m tests.lab02.reproduce_t09
./venv/bin/python -m pytest tests/lab02/test_t09_tcp_close.py -v
./venv/bin/python -m pytest -q
```

Tái hiện ngoài repo: thêm --output-dir /tmp/ids-t09 vào lệnh reproduce.
Kết quả: T09 PASS cả FIN/RST; integration 2 passed; full suite 752 passed.

## Kiểm thử bổ sung và giới hạn

74 unit tests mới ở tests/lab02/test_tcp_close.py kiểm tra closing hai chiều,
FIN/ACK gộp, missing/wrong/early ACK, retransmissions, half-close data, late
packets, RST ở các state, context cleanup, new generation/old summaries,
concurrent flows, UDP, skipped/malformed events, missing flags và atomicity.
Log regression T07/T08/T11/T13 và chi tiết API: TEST/lab02/task14/.

Tracker nhận diện logic bằng flags/direction/thứ tự đọc capture, chưa kiểm tra
sequence/ACK numbers (fixture dùng các số thông thường). Một ACK sau FIN từ
chiều đối diện là evidence heuristic. Chưa reassembly/simultaneous open/TLS.

Terminal records còn resident để late packets không tạo flow giả; bare SYN
mới sau CLOSED/RESET mở lifetime mới và lưu summary cũ. Caller cần drain queued
summaries để ghi output. Chưa idle timeout/capacity/queue limit/main CLI bài 2;
T09 không thay thế T10 DNS UDP hoặc T12 timeout.
