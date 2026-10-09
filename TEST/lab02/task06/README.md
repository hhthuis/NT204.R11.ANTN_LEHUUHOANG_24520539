# Task 06 — HTML entity decoding

Ngày kiểm thử: 09/10/2026.

## Mục đích và các file

- `ids/decoders/html.py`: decode_html(payload bytes, config, charset), trả
  TextDecodeResult gồm text/charset/status/errors.
- `ids/decoders/http.py`: thêm HttpDecodeResult.html, điều phối text body và
  dùng chung helper đọc raw HTTP body với form decoder.
- `ids/decoders/decoder.py`: HTTP dispatch đã có từ Task 05, giờ bao gồm HTML.
- `tests/lab02/test_decoder_html.py`: 49 test utility và event adapter.

## Luồng xử lý

```text
PacketEvent.application.fields
  → Content-Type text/html hoặc text/plain
  → kiểm tra Content-Encoding/Transfer-Encoding
  → đọc body_base64 (không dùng fields.body đã replacement)
  → kiểm tra max_input_bytes
  → character decode ASCII/UTF-8 theo policy
  → HTML5 entity decode đúng một lần
  → kiểm tra max_output_bytes của text UTF-8
  → ProcessedEvent.decoded.http.html
```

Body text của cả request và response đều được hỗ trợ. Charset từ header ưu
tiên hơn override caller/config; chỉ ASCII/UTF-8 được hỗ trợ ở giai đoạn này.
Body rỗng hợp lệ có text=""; không áp dụng có html=null; lỗi hoặc vượt giới
hạn có html.text=null và status/errors. PacketEvent gốc và snapshot packet
trong output giữ nguyên URI, headers, body, body_base64 và payload_base64.

## Quy tắc entity

| Input | Output | Status |
|---|---|---|
| `&lt;script&gt;` | `<script>` | ok |
| `&amp; &quot; &apos;` | `& " '` | ok |
| `&#60;` hoặc `&#x3C;` | `<` | ok |
| `&amp;lt;` hoặc `&#38;lt;` | `&lt;` | ok |
| `&unknown;` | `&unknown;` | ok |
| `&#0;`, `&#xD800;`, `&#x110000;` | U+FFFD | partial |

Hàm html.unescape của thư viện chuẩn dùng quy tắc HTML5, gồm một số entity
không có dấu `;`. Không tự gọi unescape lặp lại; unknown names giữ literal
theo quy tắc này. Numeric entity NUL, surrogate hoặc vượt U+10FFFF được ghi
invalid_html_entity (lần đầu) và thay U+FFFD. Dãy số hàng nghìn chữ số hoặc
leading zeros được xử lý trước khi chuyển int để không crash vì giới hạn
chuyển đổi số của Python. Policy strict áp dụng cho character bytes; invalid
numeric entities vẫn replacement + partial.

Không chạy script/render HTML. Đầu ra chỉ là text phân tích thêm. Không áp
dụng HTML decoding tự động lên URI, form, JSON, CSS, binary hoặc body thiếu
Content-Type. text/plain được phép tạo biểu diễn entity-decoded để phân tích;
nội dung raw vẫn là nguồn để hiểu thông điệp ban đầu.

## Lỗi và giới hạn

- Byte lỗi: replace → partial + U+FFFD; strict → error + text=null.
- Charset không hỗ trợ: unsupported_charset/error.
- Raw body thiếu/Base64 hỏng: missing_raw_html_body/invalid_html_base64.
- Input vượt giới hạn: skipped hoặc error theo limit_policy; chặn trước entity
  decode và trước cấp phát Base64 khi encoded length đã quá lớn.
- Output limit tính UTF-8 bytes sau entity decode: `&lt;` được chấp nhận với
  max_output_bytes=1; `&copy;` cần 2 bytes. Không truncate text.
- Text trung gian character-decoded được giới hạn bằng raw input size; byte
  lỗi replacement tốn tối đa 3 UTF-8 bytes mỗi input byte.
- Tổng status: error nếu field lỗi; partial nếu một field thành công nhưng
  field khác bị skip/lỗi partial; response chỉ có HTML bị limit thì skipped.
- Message chưa đủ: giữ phần text có thể decode, partial/incomplete_http_message.
- Content-Encoding/Transfer-Encoding khác identity (gzip/chunked...) chưa
  được xử lý: skipped/unsupported_http_body_encoding. Header encoding sai
  kiểu: error/invalid_http_body_encoding.
- Mọi lỗi được đưa vào ProcessedEvent.errors và reason, event tiếp theo vẫn chạy.

## Lệnh và kết quả

```bash
./venv/bin/python -m pytest tests/lab02/test_decoder_html.py -v
./venv/bin/python -m pytest -q
```

Kết quả: 49 test mới passed; toàn bộ suite 236 passed. Log thực tế tại result.txt.
Test URI/form Task 05 vẫn đạt. T02 được tái hiện bằng PCAP và commit riêng.

## Phạm vi hiện tại

Decoder chưa nối vào main CLI; chưa preprocessing/tracking/TCP reassembly,
decompression/dechunking hoặc SMTP/MIME decoding. Task tiếp theo là Task 07.
