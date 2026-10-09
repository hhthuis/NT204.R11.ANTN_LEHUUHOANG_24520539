# T04 — Invalid bytes

Ngày kiểm thử: 09/10/2026.

## Yêu cầu trong PDF

Payload không phải UTF-8 hợp lệ phải được đánh dấu lỗi/partial; chương trình
tiếp tục xử lý các packet sau đó và giữ nguyên byte gốc.

## Dữ liệu và luồng kiểm thử

`input.pcap` có hai Ethernet/IPv4/TCP packet từ 10.0.0.1:51000 đến 10.0.0.2:9999:

1. Payload `b"bad utf8: \xff\r\n"`: byte `0xff` không hợp lệ trong UTF-8.
2. Payload `b"next valid event\r\n"`: text hợp lệ, nằm sau packet lỗi.

Hai packet được đọc bởi PCAP reader và phân tích bằng parser bài 1, sau đó
chạy `decode_event()` và ghi mỗi `ProcessedEvent` thành một dòng JSONL.
`parse_status` của packet vẫn là `ok`; lỗi text được ghi riêng ở `decode_status`
và `errors` của kết quả xử lý. Payload là application UNKNOWN, không giả định
HTTP/SMTP, phù hợp phạm vi character decoder của Task 04.

Đây là script tích hợp PCAP → Parser → Decoder; main CLI bài 1 chưa được nối
decoder. Preprocessor và Tracker chưa chạy, vì vậy preprocess_status/flow còn
null, processing_action là skip_tracking.

## Files

| File | Ý nghĩa |
|---|---|
| input.pcap | Hai packet đầu vào, timestamp và byte cố định |
| expected.json | Kết quả mong đợi cho replace và strict |
| actual-replace.jsonl | Hai event thực tế với policy replace |
| actual-strict.jsonl | Hai event thực tế với policy strict |
| result.txt | Log script tái hiện, pytest T04 và toàn bộ suite |

## Lệnh tái hiện

```bash
./venv/bin/python -m tests.lab02.reproduce_t04
./venv/bin/python -m pytest tests/lab02/test_t04_invalid_bytes.py -v
```

Script sử dụng `config/default.toml` và lần lượt ghi đè invalid_bytes_policy
thành replace/strict. Nó tạo lại input, expected và hai actual outputs, kiểm tra
summary với expected trước khi báo PASS. Có thể chọn thư mục khác bằng:

```bash
./venv/bin/python -m tests.lab02.reproduce_t04 --output-dir /tmp/ids-t04
```

## Kết quả mong đợi và thực tế

| Policy | Packet | Mong đợi | Thực tế |
|---|---|---|---|
| replace | 1 | partial; text `bad utf8: �\r\n`; có lỗi decode | Đúng |
| replace | 2 | ok; text `next valid event\r\n`; không lỗi | Đúng |
| strict | 1 | error; text null; có lỗi decode | Đúng |
| strict | 2 | ok; text `next valid event\r\n`; không lỗi | Đúng |

- Cả hai policy ghi đủ hai event, ID 1/2 và source PCAP đúng.
- Byte gốc của từng packet được giữ nguyên trong payload Base64.
- Lỗi packet đầu có stage `decode`, code `invalid_character_sequence` và reason.
- Packet thứ hai được xử lý bình thường, không chịu lỗi của packet đầu.
- Pytest T04: 2 passed.
- Toàn bộ suite: 144 passed.
- Kết quả T04: PASS.
