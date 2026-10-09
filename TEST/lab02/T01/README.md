# T01 — HTTP URL decode

Ngày kiểm thử: 09/10/2026.

## Yêu cầu

URI có percent-encoding được decode đúng; raw URI trong PacketEvent còn nguyên.

## Input và kết quả

PCAP có 5 HTTP GET request trên TCP port 8080, timestamp cố định. Mỗi request
nằm đầy đủ trong một packet, đi qua PCAP reader → parser → HTTP decoder → JSONL.

| Raw URI | Decoded URI | Status |
|---|---|---|
| /search?q=%27%20OR%201%3D1 | /search?q=' OR 1=1 | ok |
| /a+b?q=x+y%2Bz | /a+b?q=x+y+z | ok |
| /caf%C3%A9?q=%2527 | /café?q=%27 | ok |
| /broken?q=%ZZ | /broken?q=%ZZ | partial |
| /next | /next | ok |

Packet 2 xác nhận dấu `+` literal giữ nguyên trong URI. Packet 3 xác nhận
UTF-8 và chỉ decode một lần. Packet 4 ghi invalid_percent_encoding và reason;
packet 5 vẫn xử lý bình thường.

## Files bằng chứng

- `input.pcap`: dữ liệu đầu vào.
- `expected.json`: summary mong đợi.
- `actual.jsonl`: 5 ProcessedEvent thực tế.
- `result.txt`: log script tái hiện và pytest.

Raw target, byte payload và parse_status gốc giữ nguyên trong `packet`.
Decoded URI nằm tại `decoded.http.uri.text`; lỗi ở `errors` và `reason`.

## Tái hiện

```bash
./venv/bin/python -m tests.lab02.reproduce_t01
./venv/bin/python -m pytest tests/lab02/test_t01_url_decode.py -v
```

Script tạo lại PCAP/expected/actual, so sánh decoded summary và raw target trước
khi báo PASS. Dùng `--output-dir /tmp/ids-t01` nếu muốn thư mục output khác.

Kết quả thực tế: script PASS, pytest 1 passed. Test xác nhận đầy đủ 5 event,
raw URI và byte payload còn nguyên sau JSON round-trip. T01: PASS.

Main CLI vẫn chỉ chạy parser bài 1; đây là script tích hợp decoder. Chưa có
preprocess, tracking hoặc TCP reassembly.
