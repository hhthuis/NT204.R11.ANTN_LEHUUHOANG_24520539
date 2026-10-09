# T11 — Concurrent flows

## Mục đích và input

Kiểm tra ≥2 flow endpoint/port khác nhau không bị gộp nhầm, packet trả lời đúng
flow và direction. Tạo input.pcap bằng Scapy: 16 Ethernet/IPv4 packets gồm 15
TCP/UDP packets không payload và 1 ICMP packet unsupported. Traffic tổng hợp,
không phải capture mạng thật. MAC đặt rõ ràng, không cần quyền raw socket.

Luồng: PcapReader → Parser → Decoder → Preprocessor → FlowTracker → actual.jsonl
và flows.json snapshot. config.toml là config processing đã dùng; Tracker timeout/
capacity chưa được áp dụng trong Task 11.

## Sáu flow

| Label | Protocol | Endpoint A | Endpoint B | Khác F1 ở |
|---|---|---|---|---|
| F1 | TCP | 10.0.0.2:51000 | 10.0.0.1:8080 | baseline |
| F2 | TCP | 10.0.0.2:51001 | 10.0.0.1:8080 | source port |
| F3 | TCP | 10.0.0.2:51000 | 10.0.0.3:8080 | destination IP |
| F4 | UDP | 10.0.0.2:51000 | 10.0.0.1:8080 | protocol, endpoint pair giống hệt |
| F5 | TCP | 10.0.0.2:51000 | 10.0.0.1:8081 | destination port |
| F6 | TCP | 10.0.0.4:51000 | 10.0.0.1:8080 | source IP |

## Thứ tự packet và expected

| Packets | Flow | Direction |
|---|---|---|
| 1–6 | F1, F2, F3, F4, F5, F6 | forward |
| 7–12 | F1, F4, F2, F3, F5, F6 | backward |
| 13 | ICMP unsupported, không có transport ports | skip_tracking, flow=null |
| 14–16 | F1, F4, F2 | forward, forward, backward |

Expected: đúng 6 active flows và 6 ID khác nhau, reverse packets quay về ID
ban đầu, ICMP không tạo flow thứ 7. ICMP parse_status=unsupported, preprocess
status=invalid vì thiếu transport bắt buộc; reason/errors còn nguyên. Ba packet
sau ICMP vẫn gắn đúng flow, không tạo phiên mới ngoài ý muốn.

Expected IDs là literal SHA-256 tính độc lập từ spec serialization, không gọi
make_flow_id() để sinh expected. expected.json chứa toàn bộ associations và
creation snapshots; kết quả thực tế phải khớp từng trường. Helper còn so sánh
packet/decoded/normalized/status/errors/reason trước và sau Tracker để bảo toàn
dữ liệu, và unit integration đọc lại JSONL/flows.json.

Thực tế: 16/16 đúng expected; 6 flows không gộp nhầm; skipped ICMP không làm
dừng processing. TCP state NEW, UDP null; counters còn zero/creation time-only.

## Tái hiện và files

```bash
./venv/bin/python -m tests.lab02.reproduce_t11
./venv/bin/python -m pytest tests/lab02/test_t11_concurrent_flows.py -v
./venv/bin/python -m pytest -q
```

- input.pcap: 16 packet tổng hợp.
- config.toml: snapshot config.
- expected.json: expected associations/flow snapshots.
- actual.jsonl: 16 ProcessedEvent, có cả skipped event và reason.
- flows.json: 6 flow creation snapshots.
- result.txt: script PASS, integration 1 passed; full suite 596 passed.

Dùng --output-dir /tmp/ids-t11 để tái hiện ngoài repo. Case này không xác nhận
counters/last_seen/TCP handshake/close/timeout, chưa phải T07/T09/T10/T12/T13.
UDP ở đây chỉ kiểm tra identity separation, chưa kiểm thử DNS query/response
statistics của T10. Main CLI bài 2 chưa được nối.
