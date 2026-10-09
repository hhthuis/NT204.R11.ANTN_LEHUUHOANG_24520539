# T03 — SMTP/MIME Base64 và Quoted-Printable

Ngày kiểm thử: 09/10/2026.

## Yêu cầu và mục đích

MIME body được decode theo encoding header; lưu decoded body và decode_status.
Kiểm tra cả Base64 và Quoted-Printable, UTF-8/ASCII, dữ liệu lỗi và event tiếp
theo vẫn chạy. Giữ nguyên raw packet, headers và body; kiểm tra cả replace/strict.

## Luồng và PCAP đầu vào

```text
input.pcap → read_pcap → parse_packet
  → detector (SMTP port + MIME header)
  → parse_smtp → parse_mime
  → decode_event → decode_mime
  → ProcessedEvent JSONL
```

PCAP tổng hợp gồm 14 MIME message trong SMTP DATA, TCP port 25. Mỗi message
nằm trọn một packet; message cuối cố ý thiếu SMTP terminator. MAC, sequence
và timestamp cố định. Không mô phỏng SMTP conversation/handshake hoặc capture
thật; mục đích là kiểm tra parser/decoder, không kiểm tra flow tracker. Parser
không cần giả lập SMTP state để nhận các mail/MIME headers trong case này.

Header X-Trace xuất hiện trước From/MIME header để kiểm tra detector không
phụ thuộc header đầu tiên. Message 2 có folded headers, uppercase media type/
encoding và quoted charset. Chỉ header CTE chọn transfer-decoder; không suy
đoán encoding từ chuỗi body.

## Expected và kết quả thực tế

| Packet | Scenario | Decoded text/body | Status replace / strict |
|---|---|---|---|
| 1 | Base64 ASCII có line wrapping | Hello | ok / ok |
| 2 | Base64 UTF-8 + folded headers | Xin chào IDS | ok / ok |
| 3 | QP UTF-8, soft break, `_`/`+`/`=3D` | Xin chào + dòng joinedline_a+b=1, giữ CRLF | ok / ok |
| 4 | Base64 có alphabet sai | text/body null; invalid_mime_base64 | error / error |
| 5 | QP escape =ZZ sai | bad=ZZ good + CRLF; invalid_quoted_printable | partial / partial |
| 6 | Base64 ra byte FF, charset UTF-8 | � / text null; decoded byte FF giữ trong Base64 | partial / error |
| 7 | QP =FF, charset UTF-8 | � + CRLF / text null; decoded bytes vẫn giữ | partial / error |
| 8 | Message hợp lệ sau các message lỗi | OK | ok / ok |
| 9 | CTE x-uuencode chưa hỗ trợ | text/body null; unsupported_transfer_encoding | skipped / skipped |
| 10 | Base64 application/octet-stream | bytes 00 FF 80; text null, không lỗi UTF-8 | ok / ok |
| 11 | Không CTE, body trông giống Base64 | SGVsbG8= + CRLF giữ literal | ok / ok |
| 12 | Multipart có boundary | text/body null; unsupported_mime_structure | skipped / skipped |
| 13 | MIME Base64 body rỗng | text="", body_length=0 | ok / ok |
| 14 | DATA thiếu terminator | Hello; incomplete_mime_message | partial / partial |

Thực tế trùng expected.json ở cả hai policy. Packet 1–13 parse_status=ok;
packet 14 parse_status=partial có parse reason gốc. Decoder không ghi đè
parse_status. Tất cả MIME fields đã decode nằm tại decoded.mime; packet vẫn
giữ byte gốc. Strict byte policy làm text=null nhưng giữ decoded bytes đã
transfer-decode thành công trong body_base64 (khi chưa vượt giới hạn).

Body QP có hard CRLF vẫn giữ CRLF trong output; soft =CRLF bị loại. Underscore
giữ literal vì đây là body, không phải RFC 2047 encoded-word header.

## Files kết quả

- input.pcap: 14 mail DATA payload.
- expected.json: decoded summary mong đợi cho replace/strict, gồm status,
  parse_status, encoding, text, body_base64 và error codes.
- actual-replace.jsonl và actual-strict.jsonl: mỗi file 14 ProcessedEvent.
- result.txt: stdout và exit code của script, integration test và toàn bộ suite.

## Tái hiện

```bash
./venv/bin/python -m tests.lab02.reproduce_t03
./venv/bin/python -m pytest tests/lab02/test_t03_smtp_mime.py -v
./venv/bin/python -m pytest -q
```

Script sinh lại input/expected/output; so sánh summary và kiểm tra raw body/
payload không đổi trước khi báo PASS. Dùng --output-dir /tmp/ids-t03 nếu muốn
output ngoài repo. Integration test đọc lại JSONL, so sánh cả header Base64,
body/payload, encoding/status, error stages/reason và message tiếp tục sau lỗi.

Kết quả thực tế: T03 PASS cả hai policy; pytest 2 passed; toàn bộ suite 303 passed.
63 test nền tảng cho Task 07 còn kiểm tra giới hạn input/output, raw thiếu,
Base64 lưu trữ lỗi, charset chưa hỗ trợ, header encoding trùng, dot transparency,
standalone MIME và regression SMTP command/response.

## Giới hạn

Chưa TCP reassembly/SMTP session state, multipart/nested MIME decoding, charset
ngoài ASCII/UTF-8, RFC 2047 hoặc TLS. Multipart được đánh dấu skipped có reason.
Main CLI chưa chạy decoder bài 2; script kiểm tra integration qua API decoder.
Preprocessor/Tracker chưa chạy: preprocess_status và flow vẫn null.
