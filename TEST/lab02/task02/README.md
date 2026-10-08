# Task 02 — Model flow và liên kết packet với flow

Ngày kiểm thử: 09/10/2026.

## Mục đích và phạm vi

Định nghĩa hợp đồng dữ liệu cho tracker bài 2 và thay `ProcessedEvent.flow`
bằng `FlowAssociation | None`. Các model độc lập với Scapy.

Task này chưa tạo flow ID, chưa tiếp nhận packet để tracking, chưa tự tính
counters, chuyển TCP state hay dọn flow timeout. Các counters/state trong test
được điền thủ công; test model không thay thế các case T07–T13 trong đề.

## Các model

| Model | Công việc |
|---|---|
| `Endpoint` | IP đã chuẩn hóa và port đã validation; bất biến |
| `FlowKey` | Khóa bất biến, dùng được trong dictionary; TCP/UDP và cặp endpoint được sắp xếp |
| `FlowRecord` | Định danh, endpoint A/B, thời gian, counters và state; tracker có thể cập nhật |
| `FlowAssociation` | Bản thông tin bất biến gồm flow ID, direction và state tại thời điểm xử lý packet |

`FlowKey` sắp xếp endpoint chỉ để lookup hai chiều. `FlowRecord.endpoint_a` là
sender đầu tiên được quan sát; A→B là forward, B→A là backward. Không suy ra
direction hay vai trò client/server từ thứ tự sắp xếp của khóa.

Chuẩn hóa IP, validation port và xác định direction từ packet được triển khai
ở các task sau; constructor `Endpoint` không thực hiện các bước đó.

## Fields thống kê

- `flow_id`, `protocol`, `application_protocol`, `endpoint_a`, `endpoint_b`.
- `start_time`, `last_seen`, `duration`.
- `packet_count`, `byte_count`.
- `forward_packet_count`, `forward_byte_count`.
- `backward_packet_count`, `backward_byte_count`.
- `syn_count`, `ack_count`, `fin_count`, `rst_count`, `state`.

Quy ước:

- Byte counters dùng tổng `PacketEvent.captured_length`, gồm header.
- Thời gian nội bộ là `datetime` có timezone; output là UTC ISO 8601.
- `duration` là property tính số giây giữa hai mốc sau khi đổi sang UTC, và
  được bổ sung vào output của `FlowRecord.to_dict()`.
- Từ chối timestamp không timezone hoặc `last_seen < start_time` lúc tạo flow.
- TCP tracker sẽ đặt state: NEW/HANDSHAKE/ESTABLISHED/CLOSING/CLOSED/RESET.
- UDP dùng `state=null`, TCP flag counters bằng 0.
- Tracker sau này chịu trách nhiệm duy trì last_seen, counters và state hợp lệ
  khi cập nhật record; dataclass không thực thi state machine.

## Input và output kiểm thử

- Input: endpoint/flow/packet tổng hợp trong `tests/lab02/test_flow_models.py`.
- Output: dictionary/JSON từ `FlowRecord.to_dict()` và `ProcessedEvent.to_dict()`.
- Không có PCAP hoặc JSONL từ pipeline tracking ở task này.

## Lệnh chạy

```bash
./venv/bin/python -m pytest tests/lab02/test_flow_models.py tests/lab02/test_processing_models.py -v
./venv/bin/python -m pytest -q
```

## Kết quả mong đợi

1. JSON round-trip giữ đủ field thống kê và tên enum là chuỗi.
2. UDP không có TCP state; timestamp UTC+7 được xuất đúng về UTC.
3. Từ chối từng trường timestamp không timezone và thứ tự thời gian sai.
4. Duration đúng theo thời gian thực đã trôi qua khi đồng hồ đổi DST.
5. Hai endpoint đảo chiều tạo khóa bằng nhau và lookup được cùng dictionary
   entry; protocol hoặc port khác tạo khóa khác. Endpoint A/B của record không đổi.
6. `ProcessedEvent.flow` giữ state tại thời điểm tạo association dù record
   chuyển state sau đó; association không cho sửa field.
7. Sửa dictionary output không ảnh hưởng endpoint gốc; endpoint của khóa bất biến.
8. Test Task 01 và các test bài 1 vẫn pass.

## Kết quả thực tế

- Có 9 test flow model mới (gồm hai trường hợp timestamp được parameterize).
- Test model bài 2: 13 passed, bao gồm 4 test Task 01.
- Toàn bộ suite: 75 passed.
- Log stdout/stderr thực tế của các lệnh nằm trong `result.txt`.
- Kết quả Task 02: PASS.
