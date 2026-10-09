# Task 12 — Flow statistics

## Mã nguồn

- `ids/flows/statistics.py`: update_statistics() trả FlowRecord mới, không sửa
  record đầu vào; cập nhật totals/directions/flags/UTC time/application label.
- `ids/flows/tracker.py`: _TrackingInput chứa metadata đã kiểm tra, kể cả bytes
  và flags; cập nhật statistics trước khi commit record/generation vào bảng.
- `ids/flows/models.py`, `ids/flows/__init__.py`: cập nhật mô tả phần đã hỗ trợ.
- `tests/lab02/test_flow_statistics.py`: 38 tests mới; các regression flow/T08/T11
  cập nhật expected thay cho creation-only counters của Task 11.

## Quy tắc thống kê

1. Mỗi accepted track() call tăng packet_count một và byte_count bằng
   normalized.captured_length (phải khớp raw PacketEvent.captured_length).
   Bao gồm capture headers, không dùng payload.length hoặc wire_length.
2. Theo direction tăng forward hoặc backward packet/byte counts; tổng luôn
   bằng hai chiều cộng lại. Packet đầu tiên được tính đúng một lần.
3. TCP: mỗi flag SYN/ACK/FIN/RST hiện diện tăng counter một lần trong packet.
   SYN/ACK tăng hai counters; duplicate flag spelling không đếm hai lần.
   Không payload/flags=[] vẫn tính packet và bytes, không suy đoán flags.
4. UDP không tăng TCP flag counters, state=null; TCP state hiện vẫn NEW.
5. Retransmissions và việc gọi track() lại cùng event đều là observations mới,
   không dedup packet_id/sequence/timestamp. Pipeline phải gọi một lần cho mỗi
   packet quan sát được; không dùng rerun để retry một packet đã đếm thành công.
6. UTC start_time=min timestamps, last_seen=max timestamps; duration đã có từ
   model là last_seen-start_time. Out-of-order timestamp không làm last_seen
   lùi; A/B vẫn theo thứ tự quan sát, không đổi orientation/flow_id.
7. UNKNOWN nâng lên nhãn hỗ trợ đầu tiên (HTTP/DNS/SMTP/MIME); nhãn đã biết
   không bị downgrade hoặc thay bằng nhãn khác. Đây là first-known heuristic,
   không phải protocol classification/stream inspection bổ sung.

## Safety và snapshots

Kiểm tra metadata trước khi thay đổi record, gồm bool/negative/float lengths,
UTC time, flags hợp lệ và length khớp raw. update_statistics() tính các giá trị
rồi dataclasses.replace() để có record độc lập. Association được dựng trước
khi thay record trong active table; generation chỉ ghi khi packet đầu thành công.

Skip/invalid metadata không đổi counters/time/app; lỗi stage=track có reason.
Fault-injection tests xác nhận lỗi updater không để lại flow/generation/counters
cập nhật dở và event tiếp theo vẫn được xử lý. Caller, raw, decoded, normalized
được giữ nguyên; export/table/removed snapshots và events cũ không đổi theo
record mới. Timestamp conversion trước min/max bảo đảm DST fold vẫn đúng.

## Tái hiện và kết quả

```bash
./venv/bin/python -m pytest tests/lab02/test_flow_statistics.py -v
./venv/bin/python -m tests.lab02.reproduce_t08 --output-dir /tmp/ids-task12-t08
./venv/bin/python -m tests.lab02.reproduce_t11 --output-dir /tmp/ids-task12-t11
./venv/bin/python -m pytest -q
```

Kết quả tại commit task: 38 tests mới passed, regression T08/T11 PASS; toàn bộ
suite 634 passed. stdout/exit code tại result.txt. Artifact Task 11/T08/T11 cũ
giữ làm snapshot lịch sử; script/test hiện tại dùng statistics thực tế.

Ví dụ regression T08: 5 packet/270 byte, forward 3/162, backward 2/108, ACK=5,
start=00:00:00Z, last=00:00:04Z, duration=4. Regression T11 vẫn 6 flow, ICMP
không tạo flow mới hoặc tăng counters/time của flow khác.

T13 sẽ có PCAP/expected/actual/flow snapshots/log và commit riêng sau mã nguồn.
Chưa handshake/close/timeout/capacity enforcement/CLI bài 2. UDP statistics cơ
bản đã có, nhưng case DNS UDP T10 vẫn thực hiện riêng ở task sau.
