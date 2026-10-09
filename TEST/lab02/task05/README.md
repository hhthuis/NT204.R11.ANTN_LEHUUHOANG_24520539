# Task 05 — HTTP URL và form decoding

Ngày kiểm thử: 09/10/2026.

## Đã triển khai

- `ids/decoders/http.py`: `decode_uri()`, `decode_form()`, `decode_http()` và
  model kết quả field HTTP.
- `decode_event()` điều phối HTTP sang decoder theo field; protocol khác tiếp
  tục dùng character decoder của Task 04.
- URI/body raw vẫn nằm nguyên trong `ProcessedEvent.packet`. Decoder không
  ghi đè parser fields hoặc sửa `PacketEvent` đầu vào.
- `tests/lab02/http_pcap_support.py` cung cấp helper tạo/đọc PCAP HTTP và ghi
  JSONL decoder để các case T01/form tái hiện được.

## URI

- Percent decoding đúng một lần: `%27%20OR%201%3D1` → `' OR 1=1`.
- Dấu `+` literal giữ nguyên trong URI, kể cả query. Không dùng form semantics
  để thay dấu `+` toàn URI và không reparse delimiter đã decode.
- `%2527` → `%27`, không decode tiếp thành dấu nháy.
- Byte percent-decoded được character-decode với ASCII/UTF-8 và policy cấu hình.
- Escape sai `%`, `%2`, `%ZZ` giữ literal, ghi invalid_percent_encoding và partial
  khi phần còn lại decode được.
- Hàm standalone nhận str UTF-8 hoặc bytes. Adapter khôi phục raw URI bytes từ
  `fields.target` Latin-1 của parser bài 1 trước decode, tránh mojibake.

## Form

- Chỉ decode form khi Content-Type là application/x-www-form-urlencoded;
  tên header/media type không phân biệt chữ hoa/thường.
- Charset header (kể cả quoted charset) được ưu tiên; thiếu thì dùng override
  của caller hoặc charset mặc định. Charset không hỗ trợ trả error/reason.
- Tách body theo `&`, tách name/value tại `=` đầu tiên trước percent decoding.
- Dấu `+` literal → space; `%2B` → dấu `+`; `%26` và `%3D` là dữ liệu, không
  trở thành delimiter để tách thêm parameter.
- Duplicate names giữ danh sách giá trị theo thứ tự; giữ blank values, tên rỗng
  và flag không có dấu `=`. Empty `&` fragments được bỏ qua.
- Đọc byte từ `body_base64`, không từ `fields.body` đã decode với replacement.
  Body rỗng được chấp nhận khi parser ghi body_length=0.

Ví dụ:

```text
tag=one&tag=two&name=Alice+Bob&plus=%2B&data=a%26b%3Dc
```

```json
{
  "tag": ["one", "two"],
  "name": ["Alice Bob"],
  "plus": ["+"],
  "data": ["a&b=c"]
}
```

## Output và giới hạn

- URI: `decoded.http.uri.text/charset/status/errors`.
- Form: `decoded.http.form.parameters/charset/status/errors`.
- Tổng: `decode_status`, `errors` và `reason` ở ProcessedEvent.
- Không có field áp dụng: null; form rỗng hợp lệ: parameters={}; form lỗi hoặc
  vượt giới hạn: parameters=null, không trả danh sách bị cắt mất phần sau.
- max_input_bytes kiểm tra raw URI/body trước percent decoding; Base64 form
  được chặn trước cấp phát khi encoded length đã vượt ngưỡng.
- max_output_bytes tính UTF-8 bytes của URI hoặc tổng name/value của toàn form,
  gồm name lặp; không phải giới hạn JSON escaping/object overhead.
- Byte lỗi dùng replace/strict của Task 03; limit dùng skip/error. Nếu một field
  skip do giới hạn và field khác thành công, status tổng là partial.
- Một field error làm status tổng error, nhưng decoded field thành công vẫn giữ.
- Message HTTP chưa hoàn chỉnh được đánh dấu partial và có reason.
- Error lặp cùng code trong form chỉ báo lần đầu, tránh tăng error list không cần thiết.

## Kiểm thử

```bash
./venv/bin/python -m pytest tests/lab02/test_decoder_http.py -v
./venv/bin/python -m pytest -q
```

41 HTTP decoder tests mới passed; toàn bộ suite 185 passed. Log tại result.txt.
Các case bắt buộc T01 và form bổ sung có artifacts/commit riêng sau task này.

## Giới hạn hiện tại

Chưa decode HTML entity/MIME, chưa reassemble TCP hoặc xử lý HTTP chunked body
trong parser. Decoder dùng parsed message của bài 1 và chưa nối vào main CLI.
Preprocessor/Tracker chưa chạy; processing_action vẫn skip_tracking.
