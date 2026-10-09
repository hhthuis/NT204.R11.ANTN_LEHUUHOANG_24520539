# Task 04 — Character decoding ASCII/UTF-8

Ngày kiểm thử: 09/10/2026.

## Đã triển khai

- `ids/decoders/text.py`: `decode_text()` trả `TextDecodeResult` gồm text,
  charset, status và lỗi theo stage/code/message.
- `ids/decoders/decoder.py`: `decode_event()` nhận `PacketEvent`, đọc byte gốc
  từ payload Base64, trả `ProcessedEvent` giữ raw packet và decoded payload.
- Cấu hình được nhận qua `DecoderConfig` của Task 03; không truyền config thì
  dùng mặc định. Charset override hỗ trợ ASCII/UTF-8 và alias tương ứng.
- Unsupported charset, byte lỗi, raw payload thiếu/Base64 hỏng và vượt giới
  hạn được chuyển thành kết quả có status/reason; không ném lỗi dữ liệu ra ngoài.
- Không dùng text preview làm nguồn; preview chỉ có 256 byte và đã thay byte lỗi.

## Quy ước xử lý

| Trường hợp | Status | Text |
|---|---|---|
| ASCII/UTF-8 hợp lệ | ok | Text đầy đủ |
| Byte lỗi, policy replace | partial | Text có ký tự thay thế U+FFFD |
| Byte lỗi, policy strict | error | null |
| Vượt giới hạn, policy skip | skipped | null |
| Vượt giới hạn, policy error | error | null |
| Charset không hỗ trợ/Base64 hỏng/raw bị thiếu | error | null |
| Packet không có payload | skipped | null |

Hàm `decode_text(b"")` vẫn trả text rỗng hợp lệ; event không có payload thì
adapter bỏ qua decode. Byte lỗi được báo bằng `invalid_character_sequence`,
ghi vị trí và lý do của sequence lỗi đầu tiên. `replace` không che giấu lỗi.

Input được giới hạn trước decode. Adapter kiểm tra độ dài Base64 trước khi
cấp phát byte payload, rồi kiểm tra số byte thực sau Base64 decode. Output limit
tính theo số byte UTF-8 của text, trước JSON escaping; U+FFFD có độ dài 3 byte.
Output vượt giới hạn bị bỏ, không cắt chuỗi hay thay đổi raw. Character decode
vẫn có buffer tạm trong phạm vi giới hạn input cấu hình, chưa phải streaming decode.

## Cách sử dụng

```python
from ids.config import load_config
from ids.decoders.text import decode_text
from ids.decoders.decoder import decode_event

config = load_config("config/default.toml").decoder
result = decode_text(b"bad:\xff", config)
print(result.status)  # partial
print(result.text)    # bad:�

# event là PacketEvent từ parser bài 1:
# processed = decode_event(event, config)
# print(processed.to_dict())
```

Decoded text được đặt tại `decoded.payload.text`, charset và status tại
`decoded.payload.charset/status`. Status tổng nằm ở `decode_status`; lỗi
được thêm vào `ProcessedEvent.errors`, reason được điền khi có lỗi/giới hạn.

## Kiểm thử

```bash
./venv/bin/python -m pytest tests/lab02/test_decoder_text.py -v
./venv/bin/python -m pytest -q
```

25 test mới kiểm tra ASCII/UTF-8/text rỗng, byte lỗi (kể cả sequence bị cắt),
replace/strict, charset sai, input sai kiểu, limit và boundary, output expansion,
giữ raw packet, Base64 hỏng/thiếu và event tiếp theo vẫn được decode.

Kết quả: 25 passed; toàn bộ suite 142 passed. Log tại `result.txt`.

## Phạm vi tiếp theo

Task này chưa decode URL, form, HTML entity hay MIME. Các module HTTP/MIME sẽ
sử dụng character decoder theo field/ngữ cảnh protocol. Chưa nối vào main CLI,
chưa thực hiện preprocess hay tracking. Bằng chứng T04 được lưu và commit riêng.
