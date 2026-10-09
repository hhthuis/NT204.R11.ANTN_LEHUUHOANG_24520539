# Task 13 — TCP handshake tracking

## Files và luồng xử lý

- ids/flows/tcp.py: TcpHandshake frozen chứa initiator và syn_ack_seen;
  update_handshake() nhận state/context/direction/flags và trả hai giá trị mới.
- ids/flows/tracker.py: context table riêng cho TCP keyed bằng bidirectional
  FlowKey; cùng flow dùng context qua hai chiều. remove_flow xóa context;
  generation mới không kế thừa evidence của lifetime trước.
- tests/lab02/test_tcp_handshake.py: 40 kiểm thử mới.
- Các test tracker/statistics/T13 cập nhật state expectations; byte/packet/
  flag counters, orientation, flow ID và thời gian giữ nguyên quy tắc Task 12.

Sau metadata validation, Tracker tính statistics mới, tính state/context mới,
đóng association snapshot rồi mới commit. Hàm xử lý không sửa record/context
đầu vào; lỗi ở statistics hoặc handshake không cập nhật dở active table,
context hoặc generation. Event skip không cung cấp evidence cho handshake.

## Quy tắc

| Quan sát | Điều kiện | State |
|---|---|---|
| ACK/data đơn lẻ | chưa thấy SYN | NEW |
| SYN | nhớ direction gửi SYN, không FIN/RST | HANDSHAKE |
| SYN/ACK | ngược direction SYN | HANDSHAKE, nhớ đã thấy SYN/ACK |
| SYN/ACK đơn lẻ | chưa thấy SYN | HANDSHAKE, chưa có initiator |
| ACK | cùng direction SYN, đã thấy SYN/ACK ngược chiều | ESTABLISHED |
| ACK sai chiều/thiếu bước | evidence chưa đầy đủ | giữ state |
| SYN/SYN/ACK gửi lại | đang handshake/established | không lùi evidence/state |
| FIN/RST | Task 14 sẽ xử lý close | không hoàn tất handshake |

SYN → SYN/ACK → ACK phải theo thứ tự quan sát trong capture, không sắp xếp
lại theo timestamp. ACK kèm PSH/ECE có thể hoàn tất. TCP không payload vẫn
được xử lý. Missing flags không được suy đoán. A/B là first-observed endpoints,
không ép initiator thành forward. UDP không có TCP context/state.

Không kiểm tra sequence/ACK-number, không xử lý simultaneous open, TCP
reassembly, automatic close/timeout/capacity. ESTABLISHED giữ nguyên khi gặp
FIN/RST trong scope Task 13; Task 14 sẽ bổ sung CLOSING/CLOSED/RESET.

## Kiểm thử và log

Lệnh chính: ./venv/bin/python -m pytest tests/lab02/test_tcp_handshake.py -v.
40 passed: complete/partial/wrong direction/order, retransmissions, late SYN
initiator backward, ACK+PSH/ECE, missing flags, contradictory SYN+FIN/RST,
concurrent flows, UDP, skipped/bad metadata, cleanup/new generation,
immutable snapshots và fault-injection tại statistics/handshake.

T08/T11/T13 tái hiện qua PCAP ở /tmp/ids-task13-t08, -t11 và -t13: tất cả PASS.
T08/T11 ACK-only vẫn NEW. T13 state mới HANDSHAKE/HANDSHAKE/ESTABLISHED,
TCP final ESTABLISHED; counters vẫn TCP 9/638, UDP 3/137, total 12/775.
Artifact cũ của các case giữ lịch sử; xem chú thích README từng case.

./venv/bin/python -m pytest -q: 675 passed tại commit mã nguồn.
Toàn bộ stdout và exit code thực tế trong result.txt. T07 có PCAP, JSONL,
flow snapshot, expected và log riêng trong commit test case tiếp theo.
