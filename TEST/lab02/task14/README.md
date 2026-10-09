# Task 14 — TCP close tracking

## Mã nguồn và luồng xử lý

- ids/flows/tcp.py: TcpClose frozen gồm forward_fin, backward_fin,
  forward_fin_acked và backward_fin_acked; update_close() trả state/context mới.
- ids/flows/tracker.py: close-context table keyed bằng bidirectional FlowKey;
  statistics → handshake → close → association → commit record/context/
  generation/summary. remove_flow xóa cả handshake lẫn close context.
- drain_completed_flows(): API lấy/xóa queued summaries của lifetimes đã bị
  thay bởi SYN mới; export_flows trả resident records và queued summaries.
- tests/lab02/test_tcp_close.py: 74 tests mới.
- Các test handshake/tracker/statistics/T13 cập nhật state expectations;
  raw/statistics/time rules và expected IDs trong cùng lifetime không đổi.

## Quy tắc đóng

| Quan sát | Evidence | State |
|---|---|---|
| FIN từ một chiều | nhớ chiều đã gửi FIN | CLOSING |
| ACK chiều ngược sau FIN | đánh dấu FIN của peer đã được ACK | CLOSING |
| FIN/ACK của peer | ACK FIN trước, đồng thời nhớ FIN của peer | CLOSING |
| ACK còn thiếu | cả hai FIN và hai ACK xác nhận đủ | CLOSED |
| FIN retransmission | không xóa evidence, không tạo FIN của chiều còn lại | giữ CLOSING/CLOSED |
| RST ở state chưa terminal | không chờ ACK; ưu tiên hơn FIN/SYN | RESET |
| SYN+FIN không RST | không dùng làm close evidence | giữ state |
| late ACK/data/FIN/RST/SYN-ACK ở terminal | không mở lại lifetime | giữ CLOSED/RESET |

ACK phải từ chiều đối diện FIN và xuất hiện sau FIN theo thứ tự capture.
Không kiểm tra sequence/ACK numbers, nên state là logic từ capture, không
khẳng định ACK đã xác nhận đúng TCP sequence. Capture thiếu packet giữ CLOSING
cho tới có evidence đầy đủ hoặc RST/timeout sau này. Capture bắt đầu bằng FIN
vẫn CLOSING, bắt đầu bằng RST vẫn RESET. UDP không có TCP state/context.

Half close: chỉ một FIN không đóng toàn bộ flow; peer vẫn có thể gửi data.
Một packet FIN/ACK có thể vừa ACK peer vừa FIN chiều của nó. SYN/SYN-ACK trong
CLOSING không quay lại handshake. Hai FIN không kèm ACK cần cả hai opposite ACK.

## Lifetime và output

Terminal record được giữ trong resident table cho tới explicit remove hoặc
bare SYN mới; không xóa ngay để các late packets không tạo flow giả. "active"
trong tên API active_flows hiện là resident table, có cả terminal records.

Valid bare SYN (không ACK/FIN/RST) sau CLOSED/RESET mở generation mới, tạo ID
khác, reset context/counters/time/app và A/B theo first sender lifetime mới.
Old summary deep-copied vào completed queue trước khi bị thay. export_flows
cho snapshot cả queue lẫn resident; drain_completed_flows lấy queue theo thứ tự
rollover rồi xóa, không sửa resident table. Caller phải ghi summaries đã drain;
remove_flow trả summary để caller xuất và không tự đẩy vào queue.

Timeout/capacity/queue bound chưa thực thi (Task 16); pipeline bài 2 cần drain
thường xuyên. Chưa phân biệt retransmitted SYN của lifetime cũ với SYN mở mới
bằng sequence numbers; bare SYN sau terminal là heuristic theo thứ tự capture.
Không hỗ trợ reassembly/simultaneous open/full TCP validation/TLS/main CLI bài 2.

## Safety và kiểm thử

Updaters chỉ trả record/context mới, không sửa đầu vào. Trước khi commit đã
kiểm tra metadata, tính statistics, hai state handlers, association và old
summary snapshot. Fault injection tại statistics/handshake/close cho packet
đầu, FIN, RST, final ACK và rollover: không cập nhật dở records/context/
generation/queue; packet hợp lệ tiếp theo vẫn xử lý đúng. Skip hoặc metadata
lỗi không cung cấp evidence. Raw/decoded/normalized/caller/event snapshots
được giữ nguyên. Late packet vẫn count observations; bytes dùng captured length.

74 tests mới: FIN hai chiều, FIN+ACK gộp, missing/wrong/early ACK, FIN retransmit,
half-closed data, duplicate final ACK, RST ở NEW/HANDSHAKE/ESTABLISHED/CLOSING,
RST priority, terminal sticky states, new generation/orientation/archive/drain,
concurrent flows/UDP, cleanup, missing flags, skip/error, observation order và
UTC time bounds, immutable contexts, malformed input và atomicity.

## Tái hiện và kết quả

```bash
./venv/bin/python -m pytest tests/lab02/test_tcp_close.py -v
./venv/bin/python -m tests.lab02.reproduce_t07 --output-dir /tmp/ids-task14-t07
./venv/bin/python -m tests.lab02.reproduce_t08 --output-dir /tmp/ids-task14-t08
./venv/bin/python -m tests.lab02.reproduce_t11 --output-dir /tmp/ids-task14-t11
./venv/bin/python -m tests.lab02.reproduce_t13 --output-dir /tmp/ids-task14-t13
./venv/bin/python -m pytest -q
```

74 new tests passed; T07/T08/T11/T13 PASS; full suite 750 passed tại source
commit. Stdout và exit code thực tế trong result.txt. T13 vẫn TCP 9/638, UDP
3/137, total 12/775; state packet 8 CLOSING, packet 9 RESET, final TCP RESET.
Các artifacts cũ giữ lịch sử; regression chạy /tmp. T09 có FIN/RST PCAP,
expected/actual/final summaries và log trong commit test case riêng tiếp theo.
