# T06 — Missing field

## Mục đích và nguồn input

Kiểm tra event thiếu field không bắt buộc có null/[] nhất quán và không exception.
Input gồm 11 PacketEvent JSONL tổng hợp tại boundary sau Parser, không phải
traffic thật/PCAP capture. source.type=pcap là source mock, không có PCAP tương
ứng. Dataclass fields giữ đủ schema; optional nested keys có thể thật sự vắng.

Luồng: input.jsonl → models → Decoder → Preprocessor → actual-default.jsonl.

## Cases và kết quả mong đợi

| Event | Scenario | Normalized / status / action |
|---|---|---|
| 1 | wire_length, TTL, fragment offset, app kind, raw payload chưa có giá trị | scalar null trong raw/model, valid, track |
| 2 | application=null | normalized.application=null, partial + missing warning, track |
| 3 | payload=null | decode skipped, partial + missing warning, track |
| 4 | TCP fields không có flags | flags=[], partial + missing warning, track; không suy đoán state |
| 5 | TCP flags=null | giống event 4 |
| 6 | DNS query thiếu answers/authorities/additionals | lists=[], question giữ và normalize domain, valid, track |
| 7 | Bốn DNS lists=null | bốn lists=[], valid, track |
| 8 | HTTP response không có headers | normalized headers={}, valid, track |
| 9 | SMTP command thiếu commands và single command | commands=[], valid, track |
| 10 | SMTP commands=null | commands=[], valid, track |
| 11 | Event hợp lệ tiếp theo | valid, track, tiếp tục xử lý |

Raw không được bổ sung flags/answers/headers. Không tạo IP, port hoặc timestamp
thay thế. UNKNOWN application và payload rỗng không cấm tracking. Default config
invalid=skip vẫn không bỏ optional missing. flow=null: action chỉ cho phép bước
Tracker tương lai, chưa có Flow Tracker runtime.

Kết quả thực tế: 11/11 khớp expected status/action/error codes; defaults cụ thể,
raw/decoded preservation, JSONL round-trip và event tiếp theo đều đạt.

## Tái hiện và bằng chứng

```bash
./venv/bin/python -m tests.lab02.reproduce_t06
./venv/bin/python -m pytest tests/lab02/test_t06_missing_fields.py -v
./venv/bin/python -m pytest -q
```

- input.jsonl: 11 PacketEvent.
- config-default.toml: invalid=skip, unsupported=mark.
- expected.json: expected status/action/error codes độc lập.
- actual-default.jsonl: 11 ProcessedEvent, gồm normalized defaults thực tế.
- result.txt: script PASS, integration test 1 passed; full suite 540 passed.

Script kiểm tra cả normalized defaults, không chỉ so sánh status. Có thể dùng
--output-dir /tmp/ids-t06 để tái hiện ngoài repo. Trường bắt buộc sai/thiếu và
collection sai kiểu thuộc T14 hoặc unit tests Task 10, không default thành []
để che mất lỗi.
