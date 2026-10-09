# T08 — Bidirectional flow

## Mục đích

Packet A→B và B→A có 5-tuple đảo chiều phải cùng flow_id, đúng direction.
Đặc biệt chọn sender đầu tiên 10.0.0.2 lớn hơn 10.0.0.1 theo key sort order để
phát hiện lỗi dùng endpoint_low làm A. A/B là thứ tự quan sát, không client/server.

## PCAP và luồng xử lý

input.pcap được sinh bằng Scapy, 5 Ethernet/IPv4/TCP ACK packets không payload;
MAC được đặt rõ ràng nên không cần quyền raw socket hoặc resolve MAC. Đây là
traffic tổng hợp, không phải capture mạng thật. Timestamps UTC xác định.

```text
PcapReader → parse_packet → decode_event → preprocess_event → FlowTracker.track
          → actual.jsonl + flows.json (inspection snapshots)
```

| Packet | Source | Destination | Expected direction |
|---|---|---|---|
| 1 | 10.0.0.2:51000 | 10.0.0.1:8080 | forward |
| 2 | 10.0.0.1:8080 | 10.0.0.2:51000 | backward |
| 3 | 10.0.0.2:51000 | 10.0.0.1:8080 | forward |
| 4 | 10.0.0.1:8080 | 10.0.0.2:51000 | backward |
| 5 | 10.0.0.2:51000 | 10.0.0.1:8080 | forward |

Expected: 1 active flow, A=10.0.0.2:51000, B=10.0.0.1:8080; tất cả cùng ID
flow-1fe9c6e2d237245fc75aa343a84d919999f77e68a25badcda8718b81b3aa7cb2.
ID expected là literal tính độc lập từ spec serialization/SHA-256, không gọi
make_flow_id() để tạo expected. Events valid/track, không errors/reason.

Thực tế: 5/5 packet đúng identity/direction, raw/decoded/normalized/status/errors
được giữ nguyên qua Tracker; JSONL và flow snapshot đọc lại khớp expected.

## Files và tái hiện

- input.pcap: đầu vào.
- config.toml: snapshot cấu hình processing; Tracker timeout/capacity chưa áp dụng.
- expected.json: expected event associations và toàn bộ creation snapshot.
- actual.jsonl: 5 ProcessedEvent thực tế.
- flows.json: 1 flow creation snapshot.
- result.txt: script PASS, integration 1 passed; full suite 595 passed.

```bash
./venv/bin/python -m tests.lab02.reproduce_t08
./venv/bin/python -m pytest tests/lab02/test_t08_bidirectional_flow.py -v
./venv/bin/python -m pytest -q
```

--output-dir /tmp/ids-t08 cho phép tái hiện ngoài repo.

## Phạm vi

TCP state hiện là NEW, chưa có handshake/close inference. Counters=0,
start_time=last_seen của packet đầu tiên, duration=0 vì Task 12 mới cập nhật
thống kê/time. Các giá trị zero trong snapshot không đại diện số packet thực
trong PCAP. Case này chỉ xác nhận T08, không thay T07/T09/T13.
main.py/CLI chưa nối bài 2; pipeline đầy đủ ở script kiểm thử này.
