# T02 — HTML entity trong text HTTP

Ngày kiểm thử: 09/10/2026.

## Yêu cầu và mục đích

Giải mã `&lt;...&gt;` trong text HTTP đúng, không crash. Bổ sung kiểm tra raw
preservation, chỉ decode một lần, charset/bytes lỗi, giới hạn phạm vi text và
chương trình tiếp tục xử lý packet sau lỗi. Giới hạn input/output có 49 unit
tests riêng của Task 06 tại tests/lab02/test_decoder_html.py.

## Luồng và đầu vào

```text
input.pcap → read_pcap → parse_packet → decode_event → ProcessedEvent JSONL
```

11 message HTTP đầy đủ, mỗi message nằm trong một TCP packet trên port 8080,
Ethernet MAC và timestamp cố định. Message 4 là POST request, còn lại là HTTP
response. Đây là PCAP tổng hợp để test parser/decoder, không mô phỏng TCP
handshake hay phiên capture thật. Charset header khác nhau theo scenario.

## Kết quả mong đợi và thực tế

| Packet | Scenario | Kết quả decoded text | Status replace / strict |
|---|---|---|---|
| 1 | Named entities trong text/html | `<script>alert("x")</script>` | ok / ok |
| 2 | Decimal/hex và amp/apos trong text/plain ASCII | `<b> <i> & '` | ok / ok |
| 3 | `&amp;lt;script&amp;gt;` | `&lt;script&gt;` | ok / ok |
| 4 | UTF-8 literal, mixed-case Content-Type, quoted charset | `Việt Nam <3 + café` | ok / ok |
| 5 | NUL/surrogate/ngoài Unicode range | `� � �`, invalid_html_entity | partial / partial |
| 6 | Raw byte FF + `&lt;bad&gt;` | `�<bad>` / null, invalid_character_sequence | partial / error |
| 7 | Message hợp lệ sau byte lỗi | `<next>` | ok / ok |
| 8 | JSON có entity literal | html=null, không áp dụng | skipped / skipped |
| 9 | Body text/html rỗng | Chuỗi rỗng | ok / ok |
| 10 | Charset iso-8859-1 chưa hỗ trợ | null, unsupported_charset | error / error |
| 11 | Body gzip thực sự, có Content-Encoding gzip | null, unsupported_http_body_encoding | skipped / skipped |

Thực tế trùng toàn bộ expected ở cả hai policy. Tất cả parse_status gốc là ok;
decode errors không ghi đè parse_status hoặc sửa packet. Raw body_base64 và
payload.base64 vẫn decode ra chính xác byte PCAP ban đầu. URI của request 4
`/submit+entity?q=&lt;x&gt;` giữ literal `+` và entity, không tự HTML-decode.

Kết quả tại decoded.http.html.text/charset/status/errors; lỗi tổng ở errors
và reason. Preprocessor/Tracker chưa chạy nên preprocess_status và flow null.
Body JSON không áp dụng có html=null; body lỗi/vượt giới hạn có html.text=null.

## Files bằng chứng

- input.pcap: PCAP chung cho hai policy.
- expected.json: summary mong đợi, tách replace và strict.
- actual-replace.jsonl: 11 ProcessedEvent thực tế, replacement policy.
- actual-strict.jsonl: 11 ProcessedEvent thực tế, strict policy.
- result.txt: stdout/exit code script, test T02 và toàn bộ suite.

## Tái hiện

```bash
./venv/bin/python -m tests.lab02.reproduce_t02
./venv/bin/python -m pytest tests/lab02/test_t02_html_entity.py -v
./venv/bin/python -m pytest -q
```

Script so sánh decoded summary với EXPECTED, kiểm tra raw body và raw URI trước
khi báo PASS; tự tạo lại PCAP/expected/actual. Dùng --output-dir /tmp/ids-t02
nếu muốn output ngoài repository. Integration test đọc lại JSONL, kiểm tra cả
payload Base64, raw body, lỗi/reason, message tiếp tục, và kết quả expected.

Kết quả thực tế: script PASS hai policy; T02 2 passed; toàn bộ suite 238 passed.

## Giới hạn

Đây là integration script của decoder, chưa phải main CLI pipeline. Chưa có
preprocess/tracker, TCP reassembly, MIME decoder, decompression hoặc dechunking.
Script không chạy/render nội dung HTML; chỉ tạo text để phân tích.
