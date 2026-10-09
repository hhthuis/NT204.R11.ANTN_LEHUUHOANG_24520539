# Task 09 — Normalization

Ngày kiểm thử: 09/10/2026.

## Các file và API

- ids/preprocessors/normalization.py: NormalizationResult(value, errors), các
  hàm normalize_protocol/ip/timestamp/domain/headers/flags/uri và normalize_packet.
- ids/preprocessors/preprocessor.py: preprocess_event(ProcessedEvent, PreprocessorConfig).
- ids/config.py và config/default.toml: hai giới hạn kích thước cho Preprocessor.
- tests/lab02/test_normalization.py: 81 tests, gồm config mới và integration HTTP.

```python
from ids.config import load_config
from ids.decoders.decoder import decode_event
from ids.preprocessors.preprocessor import preprocess_event

processed = preprocess_event(decode_event(packet_event), load_config().preprocessor)
print(processed.normalized, processed.preprocess_status)
```

Luồng: PacketEvent → Decoder → validate_event → normalize_packet → ProcessedEvent.
API chỉ nhận model đã có; không parse Scapy hoặc decode bytes lại ở Preprocessor.
Input được deepcopy; packet và decoded giữ nguyên. normalized được dựng lại từ
raw packet, không dùng URI đã percent-decode hoặc value normalized cũ làm input.

## Output normalized

```json
{
  "timestamp": "2026-10-09T00:00:00.000000Z",
  "captured_length": 54,
  "network": {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
  "transport": {"protocol": "TCP", "src_port": 51000, "dst_port": 8080, "flags": ["SYN"]},
  "application": {"protocol": "UNKNOWN", "kind": null, "fields": {}}
}
```

Đây là view metadata được chọn cho chuẩn hóa, không phải bản sao toàn bộ raw
PacketEvent. Những field parser khác và nội dung body vẫn có trong packet hoặc
decoded. Missing/bad model có network/transport/application null; không tự tạo
endpoint/time. Task 10 sẽ hoàn thiện defaults/policies và quyết định tracking.

## Quy tắc

| Field | Chuẩn hóa | Giữ nguyên |
|---|---|---|
| Protocol | trim + uppercase, riêng IPv4/IPv6 đúng canonical spelling | Unknown protocol không bị đoán thành TCP/HTTP |
| IP | biểu diễn ip_address chuẩn, strip outer whitespace | Không đoán IP sai hoặc convert IP integer |
| Timestamp | UTC ISO microsecond Z | Không dùng giờ hiện tại hoặc tự đoán timezone |
| Domain | ASCII lowercase, bỏ một trailing dot | Không Unicode casefold/IDNA lại, không đổi TXT data |
| Header | trim SP/TAB ngoài tên, lowercase tên, value list giữ thứ tự | Value không lowercase/strip/comma-join thêm |
| TCP flags | uppercase, dedup, thứ tự FIN/SYN/RST/PSH/ACK/URG/ECE/CWR/NS | Không bỏ unknown flag để tạo list có vẻ hợp lệ |
| URI/path | uppercase hex trong percent escape, non-ASCII bytes → %XX | Case path, literal +, encoded delimiters, query repeats/order, dot/slash |

DNS normalize name của questions/answers/authorities/additionals, type/class
names, domain RDATA của CNAME/NS/PTR/DNAME và địa chỉ A/AAAA. Root DNS raw name
""/"." thành "." khi có context DNS; domain rỗng ở SMTP không bị coi là root.
Các field RR khác giữ nguyên, không thêm data vào question chưa có data.

SMTP normalized.fields.commands giữ command và domain của HELO/EHLO, mailbox
của MAIL FROM/RCPT TO; local part giữ case và quoted text, null reverse-path ""
còn nguyên. Address literals [IPv4] và [IPv6:...] được chuẩn hóa IP/tag. SMTP
commands khác giữ argument, không normalize text tùy ý. SMTP/MIME message chỉ
normalize tên header; không chạy transfer/character decoder lần nữa.

HTTP request fields có method/headers/uri. uri gồm target/path/query/target_form
origin, absolute, authority hoặc asterisk. HTTP response chỉ normalize headers.
Path/query tách từ target raw, nên %3F/%26 không trở thành separator. Literal '?'
cuối target có query="", khác không query (null). Absolute target giữ scheme/host
spelling trong target; không gọi URI này là canonical toàn bộ theo RFC 3986.

Ví dụ: raw /Admin%2fA?q=x+y&x=%252f → normalized /Admin%2FA?q=x+y&x=%252f.
Decoded URI Task 05 có thể là /Admin/A?q=x+y&x=%2f; vẫn giữ ở decoded.http.uri.
Normalizer không lấy decoded URI này để decode thêm hoặc thay nguồn raw.

## Lỗi, giới hạn và trạng thái

- Errors có stage=preprocess, code prefix normalization_; giữ reason và errors
  decode/validation. Báo lần đầu mỗi normalization code, không tăng list vô hạn.
- Field sai/không hỗ trợ/limit có value=null và reason, không silently sửa hoặc
  trả substring/collection bị cắt. Những field thành công còn giữ.
- Validation invalid luôn còn invalid; normalization error trên metadata vốn
  hợp lệ làm preprocess_status=partial. decode_status không thay đổi.
- preprocessor.max_input_bytes và max_output_bytes mặc định 1 MiB, positive
  integer, reject bool/float/zero; TOML partial overrides vẫn hoạt động.
- Text field giới hạn UTF-8 bytes trước/sau transformation; URI utility string
  input UTF-8, HTTP adapter phục hồi Latin-1 bytes từ parser target.
- Header/flag/DNS record/SMTP command collections giới hạn theo compact JSON
  UTF-8 bytes, gồm key/value/structure và empty entries. Không giới hạn tổng file
  JSONL. Không tính raw packet và decoded view vào output normalization budget.
- normalized timestamp hoặc endpoint null do limit cũng không được dùng để
  tracking; Task 10 phải kiểm tra normalized required fields trước cấp action.
- Reprocessing dựng lại normalized và diagnostics, không giữ lỗi đã hết; caller
  notes và lỗi decoder vẫn giữ. flow=null, action=skip_tracking ở giai đoạn này.

## Kiểm thử

```bash
./venv/bin/python -m pytest tests/lab02/test_normalization.py -v
./venv/bin/python -m pytest -q
```

Kết quả: 81 test mới passed; toàn bộ suite 464 passed. Log tại result.txt.
Tests xác nhận normalization semantics, bad input, config/size limits, raw/decoded
preservation, JSON round-trip, DNS/SMTP fields, reprocessing và HTTP parser bytes.
T05 test input và artifact được thực hiện/commit riêng sau task này.

## Giới hạn và nguồn

Chưa policy/missing-field defaults đầy đủ, chưa cấp action track, chưa CLI/Tracker.
Không full URI equivalence/resolution, Unicode domain mapping hoặc normalize body
text ngoài các decoder đã có. Không ghép TCP/TLS/multipart mới trong task này.

Uppercase percent hex và giữ reserved delimiters theo [RFC 3986, mục 2.1–2.2 và 6.2.2.1](https://www.rfc-editor.org/rfc/rfc3986).
