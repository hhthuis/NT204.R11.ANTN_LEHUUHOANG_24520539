# Task 07 — SMTP/MIME Base64 và Quoted-Printable

Ngày kiểm thử: 09/10/2026.

## Mục đích và các file

- ids/parsers/application/mime.py: lấy headers và wire body của một MIME entity.
- ids/parsers/application/smtp.py: nhận MIME message trước khi parse command/response.
- ids/parsers/application/detector.py: nhận MIME header trên SMTP port 25/465/587/2525.
  Chỉ nhận plaintext; không giải mã TLS trên port 465/STARTTLS.
- ids/decoders/mime.py: decode_mime_body() cho bytes và decode_mime() cho event fields.
- ids/decoders/decoder.py: dispatch SMTP kind=message hoặc protocol=MIME; command/
  response vẫn dùng character decoder đã có, không coi SMTP AUTH là MIME body.
- tests/lab02/test_decoder_mime.py: 63 test adapter, utility, pipeline và regression.

## Luồng xử lý

```text
SMTP TCP payload → detector → parse_smtp → parse_mime
  → PacketEvent(application.kind=message)
  → decode_event → decode_mime
  → đọc Content-Transfer-Encoding/Content-Type/charset
  → lấy raw body từ body_base64
  → bỏ SMTP dot transparency trong biểu diễn mới
  → Base64 / Quoted-Printable / identity
  → text: ASCII/UTF-8; binary: giữ bytes
  → ProcessedEvent.decoded.mime và status/errors/reason
```

Hàm parse_mime(payload) standalone tạo protocol=MIME, không tự loại dấu chấm
hoặc SMTP terminator. parse_smtp dùng smtp_data=True cho phần mail DATA nhận
diện bằng MIME/mail header. Message nằm trong một packet; parser chưa biết
state phiên SMTP. Có thể đọc prefix DATA cùng packet để tái hiện, nhưng SMTP
client bình thường chờ response 354 rồi mới gửi mail data ở packet khác.

## Parser và dữ liệu gốc

- Các header thành dict[str, list[str]], lowercase key, unfolded continuation,
  giữ giá trị lặp theo thứ tự; không gộp critical encoding headers thành một giá trị.
- headers_base64 giữ block headers gốc; body_base64 giữ wire body gồm dot stuffing.
- PacketEvent.payload.base64 giữ toàn bộ payload, kể cả prefix DATA/terminator.
- SMTP terminator là dòng dấu chấm riêng; body còn CRLF của dòng trước terminator.
  Decoder bỏ một dấu chấm đầu dòng theo dot transparency, không sửa wire body.
- body_length=0 và body_base64=null biểu thị body rỗng; thiếu separator có
  body_length=null và decoder báo missing_raw_mime_body, không lấy lossy preview.
- Header sai cú pháp, thiếu separator/terminator hoặc bytes sau terminator được
  đánh dấu chưa complete. Phần dữ liệu đọc được vẫn được giữ.

## Quy tắc transfer decoding

| Encoding | Input | Decoded text |
|---|---|---|
| base64 | SGVsbG8= | Hello |
| quoted-printable | Xin ch=C3=A0o | Xin chào |
| quoted-printable | long=CRLFline | longline |
| quoted-printable | a_b+c=2B | a_b+c+ |
| Không có header | SGVsbG8= | SGVsbG8= (identity, không đoán) |

Chỉ decode một lần. Base64 whitespace SPACE/TAB/CR/LF được bỏ trước strict
validation; invalid alphabet/padding, noncanonical padding bits và thiếu padding
trả invalid_mime_base64/error, không lấy một phần bytes của dữ liệu hỏng.

QP decode =HH và soft line breaks =CRLF/=LF; chấp nhận lowercase hex để tương
thích. Trailing whitespace literal trên encoded line được bỏ theo MIME; =20
giữ space thật. Escape sai như =ZZ hoặc dấu = cuối body giữ literal, partial +
invalid_quoted_printable (lần đầu). Đây là body decoding, không phải RFC 2047
encoded-word nên không đổi `_` thành space. Không percent/HTML-decode tiếp.

## Output, lỗi và giới hạn

- decoded.mime: transfer_encoding, content_type, charset, text, body_base64,
  body_length, status, errors; errors/reason tổng trên ProcessedEvent.
- Text body dùng charset header, rồi caller override, rồi config.default_charset.
  Chỉ ASCII/UTF-8 được hỗ trợ. Đây là fallback cấu hình để phân tích dữ liệu,
  không thực thi mặc định US-ASCII của tất cả MIME message khi thiếu charset.
- Media type không có header dùng text/plain. Binary không ép UTF-8: text/
  charset=null, decoded bytes vẫn nằm tại body_base64. Text có byte lỗi strict
  có text=null/error nhưng decoded bytes vẫn giữ nếu không vượt giới hạn.
- Replace byte lỗi: partial + U+FFFD + invalid_character_sequence. Strict: error.
- Encoding không biết: skipped/unsupported_transfer_encoding. Multipart/* và
  message/*: skipped/unsupported_mime_structure, không decode cả boundary block.
- Critical header lặp/khác case: ambiguous_mime_header/error; header/raw data
  sai kiểu, Base64 lưu trữ hỏng hoặc charset chưa hỗ trợ có error/reason.
- max_input_bytes áp dụng riêng lên wire body và tổng CTE/Content-Type values;
  encoded storage length được chặn trước Base64 allocation. Kiểm tra raw size
  trước dot unstuffing và transfer decoding, không chỉ kích thước sau giảm.
- max_output_bytes giới hạn decoded bytes và UTF-8 text (kể cả expansion do
  replacement); không tính JSON/Base64 overhead. Vượt limit trả skipped/error
  theo policy và bỏ toàn bộ decoded body/text, giữ raw event, không truncate.
- Message chưa complete có incomplete_mime_message; decoded thành công thành
  partial. Nếu đã error/skipped, giữ trạng thái đó và thêm reason.
- Decoder không thay parse_status/parse errors của PacketEvent.

## Lệnh và kết quả

```bash
./venv/bin/python -m pytest tests/lab02/test_decoder_mime.py -v
./venv/bin/python -m pytest -q
```

63 test mới passed; toàn bộ suite 301 passed. Log stdout/exit code tại result.txt.
Các test SMTP command/response/detector và HTTP decoder cũ vẫn đạt.
T03 PCAP/JSONL bằng chứng được thực hiện trong commit riêng sau task này.

## Giới hạn và nguồn tham khảo

Chưa multipart/nested MIME, RFC 2047 header decoding, MIME charset khác ASCII/
UTF-8, TLS, TCP reassembly, SMTP session state hoặc attachment scanning.
Không ghi attachment ra file, không chạy/render nội dung đã decode. Main CLI
chưa gọi decoder bài 2; test PCAP/script dùng API để kiểm tra toàn luồng.

Tham khảo quy tắc MIME body encoding: [RFC 2045, mục 6.7–6.8](https://www.rfc-editor.org/rfc/rfc2045).
SMTP DATA và dot transparency: [RFC 5321, mục 4.1.1.4 và 4.5.2](https://www.rfc-editor.org/rfc/rfc5321).
