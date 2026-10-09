# Task 08 — Validation trước Flow Tracker

Ngày kiểm thử: 09/10/2026.

## Mục đích và các file

- ids/preprocessors/__init__.py: package cho Preprocessor.
- ids/preprocessors/validation.py: kiểm tra metadata, không sửa raw và chưa
  áp dụng chính sách hoặc chuẩn hóa nội dung.
- tests/lab02/test_validation.py: 80 test utility và luồng parser → decoder → validation.
- result.txt: log pytest của task và toàn bộ suite.
- README.md: tiến độ, giới hạn và hỗ trợ AI.

## Hai API

```python
from ids.decoders.decoder import decode_event
from ids.preprocessors.validation import validate_event, validate_packet

decoded = decode_event(packet_event)
validation = validate_packet(decoded.packet)
print(validation.status, validation.tracking_eligible, validation.reason)

processed = validate_event(decoded)
print(processed.preprocess_status, processed.processing_action)
```

validate_packet(PacketEvent) trả ValidationResult(status, tracking_eligible,
errors), với reason được suy ra từ errors. Input sai model trả invalid an toàn.
validate_event(ProcessedEvent) tạo bản sao, cập nhật preprocess_status/errors/
reason. packet, decoded và normalized của caller giữ nguyên, không share mutable
state. Tất cả lỗi của validator có stage=preprocess và code prefix validation_.

tracking_eligible chỉ có nghĩa metadata đạt điều kiện của validation để xem
xét tracking sau này. Task 08 luôn để processing_action=skip_tracking và
flow=null vì normalization và policy chưa hoàn thiện. Không tạo flow, không
tăng counters và không chuyển TCP state trong task này.

## Quy tắc bắt buộc

| Field | Điều kiện |
|---|---|
| packet_id | Integer > 0 |
| captured_length | Integer >= 0 |
| timestamp | Chuỗi datetime ISO có timezone, chuyển được sang UTC |
| network | NetworkInfo có protocol và src_ip/dst_ip hợp lệ |
| transport | TransportInfo có protocol và src_port/dst_port |
| port | Integer 0..65535, không nhận bool/float/string |
| parse_status | ok/partial/malformed/unsupported |

Các giá trị có dạng protocol khác case/whitespace được kiểm tra trên biểu diễn
tạm; raw giữ nguyên. IP khai báo IPv4 phải là địa chỉ IPv4. IPv6 đúng địa chỉ
được nhận ra là unsupported (project hiện chỉ capture IPv4), không bị gọi là
invalid_ip_address. Timestamp không timezone, ngày sai hoặc UTC conversion bị
tràn ở năm 0001/9999 được đánh dấu invalid, không đợi lỗi ở Tracker.

## Trạng thái và tracking eligibility

| Scenario | preprocess_status | tracking_eligible |
|---|---|---|
| IPv4 TCP/UDP đủ metadata | valid | true |
| SYN/SYN-ACK/ACK không payload, application UNKNOWN | valid | true |
| IP/port/timestamp bắt buộc sai hoặc thiếu network/transport | invalid | false |
| Parser malformed | invalid | false |
| Optional data lỗi, application unknown chưa hỗ trợ, parser partial ở application | partial | true nếu endpoints/time hợp lệ |
| Unsupported network/transport hoặc parser unsupported | partial | false nếu các field bắt buộc còn hợp lệ |
| Noninitial fragment hoặc TCP flags sai kiểu/tên | partial | false |
| Lỗi parser ở network/transport dù còn metadata | partial | false nếu không có lỗi bắt buộc khác |

invalid được ưu tiên khi có nhiều lỗi. Missing field bắt buộc vẫn invalid dù
parse_status=unsupported; mọi lỗi được ghi để phân biệt nguyên nhân.

## Dữ liệu tùy chọn và ý nghĩa

- wire_length nếu có phải >=captured_length; nếu thiếu thì không báo lỗi.
- TTL nếu có là integer 0..255; thiếu các field optional IPv4 không làm invalid.
- Fragment offset nếu có là integer 0..8191. Noninitial fragment cần reassembly
  trước khi tin port; validator không gán flow dựa trên port suy đoán.
- TCP fields phải là dict. Flags phải là list tên FIN/SYN/RST/PSH/ACK/URG/ECE/
  CWR/NS; case/whitespace được kiểm tra tạm. List rỗng hợp lệ. Missing flags
  partial, vẫn có thể thống kê tuple nhưng không thể suy luận TCP state. Flags
  lặp báo partial để normalization xử lý sau, không tự nhân đôi counters.
- Payload length nếu có phải nonnegative và <=captured_length. Thiếu raw của
  nonempty payload báo partial; không decode Base64 hoặc bytes lại ở validator.
- Source/application/payload model sai hoặc application fields sai kiểu báo
  partial, không tự loại flow khi endpoint/time vẫn tốt. Application protocol
  UNKNOWN là hợp lệ; FTP chưa hỗ trợ báo partial nhưng không chặn tuple TCP.
- Decode status độc lập: byte payload lỗi có thể decode_status=partial/error
  nhưng preprocess_status=valid nếu metadata hoàn chỉnh. Lỗi decode vẫn giữ
  trong errors/reason; validation không đổi decode_status hoặc raw parse_status.

## Chạy lại validation

validate_event giữ lỗi decode và lỗi stage khác. Các lỗi prefix validation_
cũ được thay bằng kết quả hiện tại, không cộng lặp vô hạn. Reason được dựng
lại từ errors hiện tại, giữ ghi chú của caller; khi sửa timestamp, reason của
lỗi timestamp đã hết không còn giữ. Association flow cũ được xóa trong bản sao
và action reset về skip_tracking để không mang authorization tracking cũ.

## Lệnh và kết quả

```bash
./venv/bin/python -m pytest tests/lab02/test_validation.py -v
./venv/bin/python -m pytest -q
```

Kết quả thực tế: 80 test mới passed; toàn bộ suite 383 passed. Tests kiểm tra
range/type/missing/unsupported metadata, timezone, raw preservation, nhiều lỗi,
revalidation, snapshot isolation và packet Scapy đi qua parser/decoder/validation.
Các test decoder, SMTP/MIME, HTTP, DNS và transport cũ vẫn đạt.

## Phạm vi tiếp theo

Task 09 tạo normalized fields và T05; Task 10 áp dụng missing/unsupported policy,
quyết định track/skip_tracking cuối cùng và thực hiện T06/T14 riêng. Config policy
đã có ở Task 03 nhưng chưa được dùng trong validator vì đây là bước chẩn đoán.
Chưa nối CLI, chưa Tracker. Tiến độ mandatory cases bài 2 vẫn T01–T04 (4/14),
không tính 80 unit tests là đã hoàn thành T14.
