# Packet Capture & Parser for IDS

Module bắt packet trực tiếp từ network interface hoặc đọc packet từ file PCAP,
phân tích IPv4, TCP, UDP, HTTP/1.x, DNS và SMTP, sau đó chuyển mỗi packet thành
một event chuẩn hóa và ghi ra file JSON Lines. Cấu trúc event được thiết kế để
các module IDS phía sau không cần truy cập trực tiếp đối tượng packet của Scapy.

## Trạng thái hiện tại

Đã triển khai:

- Đọc lần lượt từng packet từ file PCAP bằng Scapy `PcapReader`.
- Bắt packet trực tiếp từ network interface bằng Scapy `sniff`.
- Chuyển từng live packet ngay vào parsing pipeline và không lưu toàn bộ packet
  trong bộ nhớ.
- CLI yêu cầu chọn đúng một nguồn bằng `--pcap` hoặc `--interface`.
- PCAP và live capture sử dụng chung `parse_packet()` và `JsonlWriter`.
- Parse IPv4, TCP và UDP.
- Nhận diện HTTP, DNS và SMTP từ payload kết hợp thông tin transport/port.
- Nhận diện HTTP request và SMTP command trên port không chuẩn.
- Nhận diện DNS/UDP và DNS/TCP có length prefix.
- Parse HTTP request và response.
- Trích xuất HTTP method, target, version, status code, reason phrase,
  headers và body.
- Kiểm tra độ đầy đủ của HTTP body bằng Content-Length.
- Parse DNS query và response trên UDP hoặc TCP.
- Trích xuất DNS transaction ID, opcode, response code, flags, questions,
  answers, authority và additional records.
- Kiểm tra số lượng DNS record thực tế với các count trong header.
- Parse SMTP command và response.
- Trích xuất `HELO`, `EHLO`, `MAIL FROM`, `RCPT TO`, domain, mailbox và các
  tham số mở rộng của command.
- Trích xuất SMTP status code, message và multiline response.
- Hỗ trợ nhiều SMTP command hoặc response trong cùng một TCP payload.
- Ghi nhận timestamp của packet.
- Lưu payload dưới dạng Base64 và text preview.
- Chuẩn hóa dữ liệu bằng `PacketEvent`.
- Ghi mỗi event thành một dòng JSON.
- Hoàn thành đầy đủ 12/12 test case bắt buộc.
- Đánh dấu packet không hỗ trợ hoặc lỗi bằng `parse_status` và `errors`.

Chưa triển khai:

- TCP stream reassembly.

### Bài tập 2 — Model kết quả xử lý (Task 01)

- `ids/processing_models.py` định nghĩa `ProcessedEvent`, trạng thái decode,
  preprocess, action và lỗi xử lý theo stage/code/message.
- `packet` là bản sao sâu của `PacketEvent` gốc; `decoded` và `normalized`
  lưu kết quả riêng, không ghi đè raw URI/body/payload.
- Event mới có `decode_status="skipped"`, `preprocess_status=null` (chưa
  validation) và `processing_action="skip_tracking"`. Bỏ qua tracking vẫn
  cho phép ghi log event và nguyên nhân.
- Field đơn chưa có giá trị dùng `null`, danh sách dùng `[]`. Các dictionary
  `decoded`/`normalized` chỉ chứa dữ liệu tương thích JSON; byte dùng Base64.
- `flow=null` khi chưa tracking; sau Task 02 dùng model `FlowAssociation`.
- Model này chưa được nối vào CLI; Decoder, Preprocessor và Flow Tracker sẽ
  được triển khai ở các task tiếp theo.
- Kiểm tra hợp đồng dữ liệu bằng:
  `./venv/bin/python -m pytest tests/lab02/test_processing_models.py -v`.
  Đây là test nền tảng cho model, chưa phải các case T01–T14 của bài tập 2.
- Kết quả kiểm thử ngày 09/10/2026: 4 model tests passed, toàn bộ suite
  66 passed. Tài liệu và log tại `TEST/lab02/task01/`.

### Bài tập 2 — Model flow (Task 02)

- `ids/flows/models.py` định nghĩa `Endpoint`, `FlowKey`, `FlowRecord` và
  `FlowAssociation`, cùng enum protocol, direction và TCP state.
- `FlowKey` sắp xếp hai endpoint để tra cứu hai chiều, nhưng endpoint A/B trong
  `FlowRecord` giữ thứ tự quan sát: A là sender đầu tiên, A→B là forward.
- `FlowRecord` có đủ định danh, endpoint, thời gian, packet/byte counters tổng
  và hai chiều, SYN/ACK/FIN/RST counters và state theo yêu cầu bài 2.
- `byte_count` tính tổng `PacketEvent.captured_length`, gồm header; `duration`
  được tính từ hai timestamp có timezone, xuất timestamp dưới dạng UTC.
- UDP dùng `state=null`; TCP tracker sẽ cập nhật các trạng thái NEW,
  HANDSHAKE, ESTABLISHED, CLOSING, CLOSED, RESET ở task sau.
- `FlowAssociation` bất biến giữ flow ID, direction và state tại thời điểm
  xử lý packet; cập nhật `FlowRecord` không sửa state của event trước đó.
- Chưa có tạo flow ID, active table, tự cập nhật counters/state hay timeout.
  Test model không thay thế các case tracking T07–T13.
- Chạy: `./venv/bin/python -m pytest tests/lab02/test_flow_models.py -v`.
- Kết quả kiểm thử ngày 09/10/2026: 9 flow model tests mới; 13 model tests
  bài 2 passed và toàn bộ suite 75 passed.
- Tài liệu và log kiểm thử tại `TEST/lab02/task02/`.

### Bài tập 2 — Cấu hình xử lý (Task 03)

- `ids/config.py` định nghĩa config bất biến cho decoder/preprocessor/tracker,
  đọc TOML bằng thư viện chuẩn `tomllib` và báo lỗi bằng `ConfigError`.
- `config/default.toml` chứa charset ASCII/UTF-8, policy byte lỗi, giới hạn
  decode input/output, policy event invalid/unsupported, timeout TCP/UDP,
  chu kỳ kiểm tra expiry, giới hạn active flow và policy khi đầy bảng.
- Mặc định của dự án: decode input/output tối đa 1 MiB mỗi giá trị;
  TCP timeout 180 giây, UDP timeout 30 giây, kiểm tra expiry mỗi 1 giây,
  tối đa 10000 active flow. Đây là lựa chọn triển khai, không phải số do đề quy định.
- `load_config()` dùng mặc định trong code; `load_config(path)` đọc file và
  cho phép ghi đè một phần, giữ mặc định cho setting chưa có.
- Từ chối giá trị sai, timeout không hữu hạn, boolean thay số, policy không hỗ
  trợ và key viết nhầm. File lỗi/không tồn tại không âm thầm fallback.
- Các policy được mô tả trong file TOML và `TEST/lab02/task03/README.md`.
  Chưa nối cấu hình vào CLI hoặc thực thi decode/preprocess/track ở task này.
- Chạy test: `./venv/bin/python -m pytest tests/lab02/test_config.py -v`.
- Kết quả ngày 09/10/2026: 42 config tests passed, toàn bộ suite 117 passed.
  Tài liệu và log tại `TEST/lab02/task03/`.
- Hoàn thành giai đoạn 1 của bài 2: model kết quả xử lý, model flow và cấu hình.
  Bước tiếp theo: triển khai Decoder.

Ví dụ đọc cấu hình trong Python:

```python
from ids.config import load_config

config = load_config("config/default.toml")
print(config.tracker.tcp_idle_timeout)  # 180.0
```

### Bài tập 2 — Character decoder (Task 04)

- `ids/decoders/text.py` decode ASCII/UTF-8, trả text/charset/status/errors và
  sử dụng policy, giới hạn input/output của `DecoderConfig`.
- `ids/decoders/decoder.py` đọc payload Base64 đầy đủ từ `PacketEvent`, giữ
  raw packet và trả `ProcessedEvent` với `decoded.payload.text/charset/status`.
  Không dùng preview 256 byte làm nguồn decode.
- Byte lỗi: replace trả text có U+FFFD và status partial; strict trả error và
  text null. Charset sai/Base64 lỗi/raw thiếu được ghi nhận an toàn.
- Vượt giới hạn trả skipped/error theo policy, giữ raw và ghi reason. Output
  limit tính theo UTF-8 bytes trước JSON escaping, gồm expansion do replacement.
- Test: `./venv/bin/python -m pytest tests/lab02/test_decoder_text.py -v`.
- Kết quả ngày 09/10/2026: 25 test mới passed, toàn bộ suite 142 passed.
  Tài liệu/log tại `TEST/lab02/task04/`.
- HTTP URL/form được bổ sung ở Task 05, HTML ở Task 06, MIME ở Task 07;
  nối decoder vào CLI triển khai sau. T04 có bằng chứng và commit riêng.

### Bài tập 2 — T04 Invalid bytes

- PCAP gồm một packet UTF-8 lỗi và một packet hợp lệ tiếp theo; script chạy
  PCAP reader → parser bài 1 → character decoder → ProcessedEvent JSONL.
- Replace đánh dấu packet đầu partial, giữ text có U+FFFD; strict đánh dấu
  error và text null. Packet thứ hai vẫn ok trong cả hai policy, raw byte
  của hai packet giữ nguyên trong Base64.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_t04`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_t04_invalid_bytes.py -v`.
- PCAP, expected JSON, actual JSONL và tài liệu/log tại `TEST/lab02/T04/`.
- Kết quả ngày 09/10/2026: T04 2 passed; toàn bộ suite 144 passed.
  Đã hoàn thành T04; tiến độ các case tiếp theo được ghi bên dưới.

### Bài tập 2 — HTTP URL/form decoder (Task 05)

- `ids/decoders/http.py` percent-decode URI một lần, giữ literal `+` trong URI;
  form decoder xử lý `+` thành space, `%2B` thành `+`, tách delimiter trước decode.
- Form chỉ chạy với Content-Type application/x-www-form-urlencoded, hỗ trợ
  charset header ASCII/UTF-8, giữ giá trị lặp và blank values.
- `decode_event()` điều phối HTTP theo field; kết quả tại `decoded.http.uri`
  và `decoded.http.form`. Packet/raw target/body/payload giữ nguyên.
- Khôi phục URI bytes từ target Latin-1 của parser và form bytes từ body_base64,
  tránh đọc text body đã thay byte lỗi.
- Có status/reason cho escape sai, byte lỗi, Base64 hỏng, charset không hỗ trợ,
  message chưa đầy đủ và vượt giới hạn input/output theo DecoderConfig.
- Test: `./venv/bin/python -m pytest tests/lab02/test_decoder_http.py -v`.
- Kết quả ngày 09/10/2026: 41 test HTTP mới passed; toàn bộ suite 185 passed.
  Tài liệu/log tại `TEST/lab02/task05/`; T01/form có commit bằng chứng riêng.
- HTML decoding được bổ sung ở Task 06, MIME ở Task 07; nối decoder vào
  main CLI triển khai sau.

### Bài tập 2 — T01 HTTP URL decode

- PCAP 5 HTTP GET request kiểm tra percent decoding, UTF-8, giữ literal `+`,
  chỉ decode một lần, escape sai được đánh dấu partial và request tiếp theo vẫn ok.
- Raw URI và payload byte giữ nguyên; output decoder tại `decoded.http.uri`.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_t01`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_t01_url_decode.py -v`.
- Input, expected, actual JSONL và tài liệu/log tại `TEST/lab02/T01/`.
- Kết quả ngày 09/10/2026: T01 PASS, pytest 1 passed.
  Đã hoàn thành T01/T04 bài 2; các case còn lại sẽ triển khai sau.

### Bài tập 2 — Kiểm thử HTTP form bổ sung

- PCAP 7 POST request kiểm tra form parameter lặp, `+`/`%2B`, encoded
  delimiter, UTF-8/charset header, lỗi percent/byte, event tiếp theo, non-form
  Content-Type và body rỗng. Raw body/payload giữ nguyên trong output.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_http_form`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_http_form_pcap.py -v`.
- Bằng chứng tại `TEST/lab02/http-form/`; case form 1 passed.
- Kết quả ngày 09/10/2026 sau Task 05/T01/form: toàn bộ suite 187 passed.
  T01 và T04 đã hoàn thành (2/14); form là kiểm thử chức năng bổ sung.

### Bài tập 2 — HTML entity decoder (Task 06)

- `ids/decoders/html.py`: character-decode ASCII/UTF-8 rồi HTML5 entity-decode
  đúng một lần. Hỗ trợ named/decimal/hex entities: `&lt;script&gt;` → `<script>`,
  `&#60;`/`&#x3C;` → `<`; `&amp;lt;` → `&lt;`.
- Adapter HTTP áp dụng cho body có Content-Type text/html hoặc text/plain,
  request và response. Đọc body_base64, giữ nguyên PacketEvent/body/payload;
  kết quả riêng tại `decoded.http.html.text/charset/status/errors`.
- Không tự HTML-decode URI/form, JSON, binary, CSS hoặc body thiếu Content-Type.
  Với text/plain, đây là biểu diễn bổ sung để phân tích; raw text vẫn giữ nguyên.
- Unknown named entities giữ literal theo HTML5. Numeric entity NUL/surrogate/
  ngoài Unicode range được thay U+FFFD, partial và invalid_html_entity.
  Numeric reference rất dài không gây lỗi chuyển số nguyên; errors được giới hạn.
- Byte lỗi theo replace/strict; charset sai/Base64 lỗi/thiếu body ghi error/reason.
  Input bị chặn trước decode; output limit tính UTF-8 bytes sau entity decoding,
  không cắt text. HTTP chưa đầy đủ có partial/reason.
- Body gzip/chunked được skipped có reason vì chưa có decompression/dechunking.
- Test: `./venv/bin/python -m pytest tests/lab02/test_decoder_html.py -v`.
- Kết quả ngày 09/10/2026: 49 test mới passed; toàn bộ suite 236 passed.
  Tài liệu/log tại `TEST/lab02/task06/`; T02 có bằng chứng/commit riêng.
- Decoder vẫn chạy qua API/script kiểm thử; main CLI chưa gọi module bài 2.

### Bài tập 2 — T02 HTML entity

- PCAP 11 HTTP message kiểm tra named/decimal/hex entities, decode một lần,
  UTF-8 và charset header, numeric entity lỗi, byte lỗi và message kế tiếp,
  không decode JSON, body rỗng, charset không hỗ trợ và bỏ qua gzip có reason.
- Chạy cả replace/strict; raw URI, body và payload giữ nguyên trong JSONL.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_t02`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_t02_html_entity.py -v`.
- PCAP, expected JSON, actual-replace/actual-strict JSONL và tài liệu/log:
  `TEST/lab02/T02/`.
- Kết quả ngày 09/10/2026: T02 PASS cả hai policy, pytest 2 passed;
  toàn bộ suite 238 passed. T01/T02/T04 hoàn thành (3/14), form là case bổ sung.

### Bài tập 2 — SMTP/MIME decoder (Task 07)

- `ids/parsers/application/mime.py` đọc header/body MIME, giữ raw headers/body
  bằng Base64, giữ header lặp và unfold continuation. SMTP parser nhận message
  ngoài command/response; detector nhận MIME trên các SMTP port đã hỗ trợ.
- `ids/decoders/mime.py` giải mã đúng một lần theo Content-Transfer-Encoding:
  Base64 và Quoted-Printable; thiếu header dùng identity 7bit, không đoán Base64.
- Base64 hỗ trợ whitespace/line wrapping; alphabet/padding sai trả error.
  QP hỗ trợ =HH, soft line breaks; dấu `_`/`+` literal giữ nguyên; escape sai
  giữ literal và partial, không silently bỏ dấu `=` cuối body.
- Text được character-decode ASCII/UTF-8; charset header ưu tiên, thiếu thì
  dùng caller/config. Binary giữ decoded bytes Base64, không ép thành UTF-8.
- Kết quả tại `decoded.mime`: encoding/media type/charset/text/body_base64/
  body_length/status/errors. Dữ liệu gốc nằm nguyên trong `packet`.
- SMTP DATA terminator được tách ở parser; dot transparency được xử lý ở
  decoder, wire body và payload gốc giữ nguyên. DATA thiếu terminator có partial.
- Byte lỗi/charset sai/header encoding lặp/raw thiếu/Base64 hỏng có status/reason;
  giới hạn input/output dùng DecoderConfig, vượt limit không truncate dữ liệu.
- Multipart/nested MIME và encoding chưa hỗ trợ được skipped có reason;
  chưa TCP reassembly/SMTP session state hoặc TLS decryption.
- Test: `./venv/bin/python -m pytest tests/lab02/test_decoder_mime.py -v`.
- Kết quả ngày 09/10/2026: 63 test mới passed; toàn bộ suite 301 passed.
  Tài liệu/log tại `TEST/lab02/task07/`; T03 có bằng chứng/commit riêng.
- Main CLI vẫn chỉ chạy parser; bài 2 decoder chạy qua API/script kiểm thử.

### Bài tập 2 — T03 SMTP Base64/Quoted-Printable

- PCAP 14 mail DATA message gồm Base64 ASCII/UTF-8/line wrapping, QP UTF-8/
  soft line breaks, lỗi transfer encoding/character bytes và message tiếp theo,
  binary decoded bytes, không đoán Base64 khi thiếu CTE, multipart skip, body
  rỗng và SMTP DATA thiếu terminator. Chạy hai policy replace/strict.
- So sánh decoded body/text/status với expected, giữ nguyên raw headers/body/
  payload trong output, errors/reason phù hợp và không dừng sau message lỗi.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_t03`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_t03_smtp_mime.py -v`.
- PCAP/expected/actual JSONL và tài liệu/log tại `TEST/lab02/T03/`.
- Kết quả ngày 09/10/2026: T03 PASS cả hai policy, pytest 2 passed; toàn bộ
  suite 303 passed. Đã hoàn thành T01–T04 (4/14); form là case bổ sung.

### Bài tập 2 — Event validation (Task 08)

- `ids/preprocessors/validation.py`: validate_packet() trả ValidationResult
  gồm status/tracking_eligible/errors/reason; validate_event() trả bản sao
  ProcessedEvent với preprocess_status và lỗi stage=preprocess.
- Kiểm tra packet_id, captured_length, IP/network protocol, TCP/UDP và port
  0..65535; timestamp ISO có timezone và chuyển được sang UTC. Không coi bool/
  float/string là integer hợp lệ và không sửa raw values khi kiểm tra.
- valid: metadata đạt kiểm tra; invalid: field bắt buộc sai/thiếu hoặc packet
  malformed; partial: optional data lỗi/thiếu, parser partial hoặc unsupported.
- Unsupported network/transport, fragment không phải đầu, TCP flags sai hoặc
  parse errors ở network/transport không đủ điều kiện tracking. Lỗi application
  không tự loại metadata TCP/UDP tốt; UNKNOWN và payload rỗng vẫn được hỗ trợ.
- Decode status độc lập với validation; giữ errors/reason trước đó, cập nhật
  lỗi validation khi chạy lại, không sửa packet/decoded/normalized của caller.
- Đây là validation stage: action vẫn skip_tracking và flow=null cho tới khi
  hoàn thiện normalization/policy. Chưa dùng policy mark/skip ở task này.
- Test: `./venv/bin/python -m pytest tests/lab02/test_validation.py -v`.
- Kết quả ngày 09/10/2026: 80 test mới passed; toàn bộ suite 383 passed.
  Tài liệu/log tại `TEST/lab02/task08/`. T14 chưa hoàn thành; sẽ có artifacts
  riêng sau khi Preprocessor có đầy đủ normalization/policy.
- Validation được nối normalization ở Task 09 qua API; chưa nối vào main CLI.

### Bài tập 2 — Normalization (Task 09)

- `ids/preprocessors/normalization.py`: canonical protocol/IP/time/domain/
  header names/TCP flags/URI vào một view riêng trong ProcessedEvent.normalized.
- `ids/preprocessors/preprocessor.py`: preprocess_event() nối validation →
  normalization, giữ packet/decoded và lỗi stage trước đó; không tự tạo default
  IP/port/time khi dữ liệu sai. Chạy lại không cộng lặp lỗi hoặc giữ lỗi đã hết.
- Protocol canonical TCP/UDP/HTTP/DNS/SMTP/MIME/UNKNOWN, IPv4/IPv6; IP canonical,
  timestamp UTC microsecond Z; port/kích thước hợp lệ giữ integer.
- Domain DNS và SMTP dùng ASCII case normalization, bỏ một trailing dot; không
  áp dụng IDNA/Unicode mapping lần nữa. SMTP mailbox giữ local-part/quoted text,
  chỉ chuẩn hóa domain; hỗ trợ null reverse-path và IPv4/IPv6 address literal.
- Headers thành dict[str, list[str]], lowercase tên, giữ nguyên value và mọi giá
  trị lặp/case collision. DNS normalize question/RR names và CNAME/NS/PTR/DNAME
  domain data, A/AAAA IP data; TXT data giữ nguyên. Flags dedup và xếp theo bit order.
- HTTP URI bắt đầu từ raw target bytes: chỉ uppercase percent hex, percent-
  represent non-ASCII wire bytes; không decode tiếp, đổi '+' hoặc lowercase path,
  không collapse slash/dot-segments/sort query. Tách path/query trước decoded view.
- Origin/absolute/authority/asterisk target có target_form; form không hỗ trợ hoặc
  dữ liệu sai có normalization error/reason. Field lỗi/limit thành null, field
  thành công vẫn giữ; preprocess invalid không bị chuyển thành valid.
- Thêm preprocessor.max_input_bytes/max_output_bytes trong config/TOML (1 MiB
  mặc định). Giới hạn text tính UTF-8 bytes; collection tính compact JSON UTF-8
  bytes. Vượt limit bỏ cả field, không truncate và không thay đổi raw.
- Test: `./venv/bin/python -m pytest tests/lab02/test_normalization.py -v`.
- Kết quả ngày 09/10/2026: 81 test mới passed; toàn bộ suite 464 passed.
  Tài liệu/log tại `TEST/lab02/task09/`; T05 có bằng chứng và commit riêng.
- Tại commit Task 09, action vẫn skip_tracking, flow=null. Task 10 bên dưới
  bổ sung policy/action; chưa nối CLI.

### Bài tập 2 — T05 Normalization

- Input JSONL gồm 10 PacketEvent fixture: bốn cặp HTTP/DNS/SMTP EHLO/SMTP mailbox
  có cùng ý nghĩa nhưng khác case/format, một timestamp lỗi và event hợp lệ kế tiếp.
- So sánh toàn bộ normalized với expected, xác nhận mỗi cặp cho cùng view;
  raw PacketEvent và decoded fields giữ nguyên, duplicate header values và case
  local-part còn nguyên. Không double-decode URI hoặc thay '+' thành space.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_t05`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_t05_normalization.py -v`.
- Input JSONL/expected JSON/actual JSONL và tài liệu/log tại `TEST/lab02/T05/`.
  Đây là synthetic event input cho Preprocessor, không phải PCAP capture thật.
- Kết quả ngày 09/10/2026: T05 PASS, pytest 1 passed; toàn bộ suite 465 passed.
  Đây là snapshot tại Task 09 (5/14). Từ Task 10, script/test T05 dùng DNS
  missing lists=[] và action track cho metadata hợp lệ; giữ snapshot cũ, chạy
  regression ngoài repo với log tại TEST/lab02/task10/result.txt.

### Bài tập 2 — Missing/unsupported data và policy (Task 10)

- Preprocessor nối validation → normalization → policy, cấp track khi cả raw
  và normalized metadata an toàn. flow vẫn null vì chưa có Tracker runtime.
- DNS lists và SMTP commands thiếu dùng []; TCP flags thiếu dùng [] kèm warning,
  không suy đoán state; headers thiếu dùng {}; missing model/scalar dùng null.
  Malformed/over-limit field giữ null kèm lỗi, không bị default che mất; raw và
  decoded không đổi. Defaults vẫn chịu normalization limits.
- invalid_event_policy áp dụng malformed/normalization issues, gồm optional
  data lỗi trên partial event. unsupported_event_policy áp dụng dữ liệu chưa
  hỗ trợ. mark giữ cảnh báo và chỉ track khi metadata an toàn; skip giữ event
  log nhưng skip_tracking. Required invalid/unsafe luôn skip kể cả mark.
- Optional missing, repaired duplicate flags và application parser partial
  warning không tự kích hoạt invalid policy. UNKNOWN/TCP/UDP được tracking;
  decode errors độc lập. Network/transport errors và noninitial fragments chặn.
- Decoder không crash khi application/payload model null hoặc sai kiểu.
  Rerun thay cấu hình/sửa input tính lại action, bỏ diagnostics đã hết.
- Test: `./venv/bin/python -m pytest tests/lab02/test_preprocessor_policy.py -v`.
- Kết quả tại commit task: 74 test mới passed, T05 regression PASS, toàn bộ
  suite 539 passed. Quy tắc/API/log tại `TEST/lab02/task10/`.
- T06/T14 được thực hiện và commit riêng sau phần mã nguồn Task 10.
  Hai case đã hoàn thành, xem các mục tiếp theo; Preprocessor API đã đủ
  validation/normalization/defaults/policy, CLI bài 2 vẫn chưa được nối.

### Bài tập 2 — T06 Missing field

- 11 synthetic PacketEvent JSONL: optional scalars/model null, missing/null TCP
  flags, DNS lists thiếu/null, HTTP headers thiếu, SMTP commands thiếu/null và
  event hợp lệ tiếp theo. Source là mock, không phải PCAP capture mạng thật.
- Defaults null/[]/{} đúng ngữ cảnh; không sửa raw hay decoded, không tự tạo
  endpoint/time/state. Optional missing vẫn được track dưới invalid=skip nếu
  metadata an toàn; flow=null vì chưa triển khai Tracker runtime.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_t06`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_t06_missing_fields.py -v`.
- Input/config/expected/actual và README/log tại `TEST/lab02/T06/`.
- Kết quả: T06 PASS 11/11, integration 1 passed; full suite 540 passed.
  Đây là snapshot tại commit T06; T14 có commit riêng bên dưới.

### Bài tập 2 — T14 Malformed/unsupported event

- 23 synthetic PacketEvent, chạy cả 4 tổ hợp invalid/unsupported mark/skip
  (92 lượt xử lý). Required IP/port/time/model sai, parser malformed/unsupported,
  IPv6/SCTP/FTP, optional TTL/URI/DNS fields sai, unsafe flags/fragment/lower-layer
  parse error, optional model sai kiểu, mixed errors và event hợp lệ kế tiếp.
- Không exception; status/action/error codes khớp expected; invalid hoặc unsafe
  metadata luôn skip dù mark. Optional malformed/unsupported áp dụng policy;
  mixed errors không để mark ghi đè skip. Raw/decoded và reason còn nguyên.
- Tái hiện: `./venv/bin/python -m tests.lab02.reproduce_t14`.
- Test: `./venv/bin/python -m pytest tests/lab02/test_t14_malformed_events.py -v`.
- Input/bốn config/expected/bốn actual JSONL và README/log tại `TEST/lab02/T14/`.
  Fixture ở model boundary, không phải capture thật hoặc JSON syntax parser.
- Kết quả: T14 PASS 92/92, integration 1 passed; full suite 541 passed.
- Mandatory cases T01–T06 và T14 hoàn thành: 7/14. T07–T13 thuộc Tracker.

## Yêu cầu môi trường

- Python 3.12 trở lên.
- Linux hoặc WSL được khuyến nghị.
- Live capture cần quyền root hoặc Linux capabilities để truy cập raw socket.

Phiên bản đã dùng khi kiểm thử gần nhất ngày 28/09/2026:

- Python 3.12.3.
- Scapy 2.7.0.
- pytest 9.1.1.

## Cài đặt

```bash
python -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Sử dụng

Chương trình yêu cầu chọn đúng một trong hai nguồn packet: file PCAP hoặc network
interface.

### Đọc file PCAP

Đọc một file PCAP và ghi kết quả ra JSONL:

```bash
python main.py \
  --pcap path/to/input.pcap \
  --output output/events.jsonl
```

Ví dụ với dữ liệu kiểm thử transport:

```bash
python -m tests.generate_transport_pcap

python main.py \
  --pcap TEST/transport-test.pcap \
  --output TEST/transport-test.jsonl
```

Kết quả mong đợi:

```text
Created TEST/transport-test.pcap with 5 packets
Processed 5 packets. Output: TEST/transport-test.jsonl
```

### Live capture

Xem danh sách interface có trên máy:

```bash
ip link show
```

Hoặc lấy danh sách interface Scapy có thể sử dụng:

```bash
python - <<'PY'
from scapy.interfaces import get_if_list
print(get_if_list())
PY
```

Bắt packet trực tiếp từ `eth0` và ghi kết quả ra JSONL:

```bash
sudo ./venv/bin/python main.py \
  --interface eth0 \
  --output output/live-events.jsonl
```

Mỗi packet được chuyển ngay vào pipeline và ghi thành một dòng JSON. Nhấn
`Ctrl+C` để dừng capture; chương trình sẽ đóng file output và in tổng số packet
đã xử lý.

Không truyền đồng thời `--pcap` và `--interface`. CLI sẽ báo lỗi nếu thiếu cả hai
nguồn hoặc nếu cả hai cùng xuất hiện.

## Pipeline xử lý

```text
PCAP file ──→ PcapReader ──┐
                           ├──→ process_packet()
Interface ──→ sniff ───────┘
                                  ↓
                            parse_packet()
                                  ↓
IPv4 parser
    ↓
TCP/UDP parser
    ↓
Application protocol detector
    ├── HTTP parser
    ├── DNS parser
    ├── SMTP parser
    └── UNKNOWN
    ↓
PacketEvent
    ↓
JSONL writer
```

Hai nguồn cùng gọi `parse_packet()` nên không có parser riêng cho live traffic và
PCAP.

## Cấu trúc project

```text
main.py                         Điểm khởi chạy chương trình
ids/
├── cli.py                     CLI và điều phối PCAP/live capture
├── models.py                  Cấu trúc PacketEvent
├── pipeline.py                Pipeline parse packet
├── capture/
│   ├── pcap.py                Đọc file PCAP
│   └── live.py                Bắt packet từ network interface
├── parsers/
│   ├── network.py             IPv4 parser
│   ├── transport.py           TCP/UDP parser
│   └── application/
│       ├── detector.py        Nhận diện HTTP, DNS và SMTP
│       ├── http.py            HTTP/1.x request/response parser
│       ├── dns.py             DNS query/response parser
│       ├── smtp.py            SMTP command/response/MIME adapter
│       └── mime.py            Header và raw body của MIME entity
└── output/
    └── jsonl.py               JSON Lines writer
tests/                         Kiểm thử tự động và script sinh PCAP
TEST/                          PCAP, JSONL, log và tài liệu kiểm thử
```

## Cấu trúc event

Mỗi dòng trong output là một JSON object. Ví dụ rút gọn:

```json
{
  "schema_version": "1.0",
  "packet_id": 1,
  "timestamp": "2026-09-17T00:00:00.000000Z",
  "source": {
    "type": "pcap",
    "name": "transport-test.pcap"
  },
  "network": {
    "protocol": "IPv4",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2"
  },
  "transport": {
    "protocol": "TCP",
    "src_port": 51000,
    "dst_port": 8080,
    "fields": {
      "flags": ["SYN"],
      "sequence_number": 1000
    }
  },
  "application": {
    "protocol": "UNKNOWN",
    "kind": null,
    "fields": {}
  },
  "parse_status": "ok",
  "errors": []
}
```

## Kiểm thử

Chạy toàn bộ test:

```bash
python -m pytest -v
```

Chạy từng test case transport:

```bash
python -m pytest -v tests/test_pcap_pipeline.py::test_tcp_handshake
python -m pytest -v tests/test_pcap_pipeline.py::test_tcp_data
python -m pytest -v tests/test_pcap_pipeline.py::test_udp_data
```

Chạy test cho application protocol detector:

```bash
python -m pytest -v tests/test_application_detector.py
```

Chạy các test HTTP bắt buộc:

```bash
python -m pytest -v tests/test_http_get.py
python -m pytest -v tests/test_http_post.py
python -m pytest -v tests/test_http_response.py
```

Chạy các test DNS bắt buộc:

```bash
python -m pytest -v tests/test_dns_query.py
python -m pytest -v tests/test_dns_response.py
```

Chạy các test SMTP hiện có:

```bash
python -m pytest -v tests/test_smtp_parser.py
python -m pytest -v tests/test_smtp_command.py
python -m pytest -v tests/test_smtp_response.py
```

Chạy test unknown protocol:

```bash
python -m pytest -v tests/test_unknown_protocol.py
```

Chạy test malformed packet:

```bash
python -m pytest -v tests/test_malformed_packet.py
```

Chạy test live capture adapter và live pipeline:

```bash
python -m pytest -v tests/test_live_capture.py
python -m pytest -v tests/test_live_pipeline.py
```

Các test live capture tự động mock Scapy `sniff`, vì vậy không cần quyền root,
không phụ thuộc interface của máy chạy test và vẫn kiểm tra packet được chuyển
vào pipeline chung rồi ghi ra JSONL.

Tài liệu và log kết quả:

- [TCP handshake](TEST/tcp-handshake.md)
- [TCP data](TEST/tcp-data.md)
- [UDP data](TEST/udp.md)
- [PCAP đầu vào](TEST/transport-test.pcap)
- [JSONL đầu ra](TEST/transport-test.jsonl)
- [HTTP GET](TEST/http-get.md)
- [HTTP POST](TEST/http-post.md)
- [HTTP response](TEST/http-response.md)
- [DNS query](TEST/dns-query.md)
- [DNS response](TEST/dns-response.md)
- [SMTP command](TEST/smtp-command.md)
- [SMTP response](TEST/smtp-response.md)
- [Unknown protocol](TEST/unknown-protocol.md)
- [Malformed packet](TEST/malformed-packet.md)

TC-09 SMTP command có đầy đủ artifact:

- [PCAP đầu vào](TEST/smtp-command.pcap)
- [JSONL đầu ra](TEST/smtp-command.jsonl)
- [Log kiểm thử](TEST/smtp-command-result.txt)

TC-10 SMTP response có đầy đủ artifact:

- [PCAP đầu vào](TEST/smtp-response.pcap)
- [JSONL đầu ra](TEST/smtp-response.jsonl)
- [Log kiểm thử](TEST/smtp-response-result.txt)

TC-11 unknown protocol có đầy đủ artifact:

- [PCAP đầu vào](TEST/unknown-protocol.pcap)
- [JSONL đầu ra](TEST/unknown-protocol.jsonl)
- [Log kiểm thử](TEST/unknown-protocol-result.txt)

TC-12 malformed packet có đầy đủ artifact:

- [PCAP đầu vào](TEST/malformed-packet.pcap)
- [JSONL đầu ra](TEST/malformed-packet.jsonl)
- [Log kiểm thử](TEST/malformed-packet-result.txt)

Kết quả kiểm thử hiện tại:

```text
62 passed
```

Tiến độ test case bắt buộc: 12/12, đạt 100%.

## Giới hạn hiện tại

- Live capture đã có automated test bằng packet giả lập, nhưng chưa lưu artifact
  của một phiên capture thủ công trên network interface thật trong `TEST/`.
- PCAP kiểm thử transport được tạo bằng Scapy, chưa phải capture từ traffic
  thực tế.
- HTTP parser xử lý một message nằm trọn trong một TCP packet; chưa ghép HTTP
  message bị chia trên nhiều TCP segment.
- Chưa giải mã `Transfer-Encoding: chunked`; body chunked hiện được giữ ở
  dạng raw body.
- Header trùng tên được nối bằng dấu phẩy trong output chuẩn hóa.
- DNS response bắt buộc hiện được kiểm thử với bản ghi `A`; parser lưu được
  các resource record khác dưới dạng dữ liệu JSON an toàn nhưng chưa có test
  riêng cho từng loại record.
- SMTP command và response hiện được kiểm thử bằng PCAP sinh bởi Scapy;
  chưa có capture SMTP từ lưu lượng thực tế.
- Malformed packet test sử dụng các frame bị cắt và payload lỗi được tạo có
  chủ đích bằng Scapy; chưa kiểm thử với PCAP hỏng thu từ môi trường thật.
- Parser làm việc trên từng packet và chưa ghép dữ liệu từ nhiều TCP segment.
- Chương trình mới hỗ trợ IPv4 với TCP hoặc UDP.

## Sử dụng AI

- Công cụ: OpenAI Codex.
- Mục đích: tư vấn kiến trúc, thiết kế cấu trúc event, hướng dẫn và hỗ trợ
  triển khai PCAP reader, live capture, IPv4/TCP/UDP parser, application protocol
  detector, pipeline, JSONL writer, kiểm thử tự động và tài liệu kiểm thử.
- Các phần có sử dụng hỗ trợ AI: `ids/models.py`, `ids/output/jsonl.py`,
  `ids/processing_models.py`, `tests/lab02/test_processing_models.py`,
  `ids/flows/models.py`, `tests/lab02/test_flow_models.py`,
  `ids/config.py`, `config/default.toml`, `tests/lab02/test_config.py`,
  `ids/decoders/text.py`, `ids/decoders/decoder.py`,
  `tests/lab02/test_decoder_text.py`,
  `ids/decoders/http.py`, `tests/lab02/test_decoder_http.py`,
  `ids/decoders/html.py`, `tests/lab02/test_decoder_html.py`,
  `ids/parsers/application/mime.py`, `ids/decoders/mime.py`,
  `tests/lab02/test_decoder_mime.py`,
  `ids/preprocessors/__init__.py`, `ids/preprocessors/validation.py`,
  `tests/lab02/test_validation.py`,
  `ids/preprocessors/normalization.py`, `ids/preprocessors/preprocessor.py`,
  `tests/lab02/test_normalization.py`,
  `ids/preprocessors/policy.py`, `tests/lab02/test_preprocessor_policy.py`,
  `tests/lab02/preprocessor_case_support.py`,
  `tests/lab02/reproduce_t06.py`, `tests/lab02/test_t06_missing_fields.py`,
  `tests/lab02/reproduce_t14.py`, `tests/lab02/test_t14_malformed_events.py`,
  `tests/lab02/event_file_support.py`, `tests/lab02/reproduce_t05.py`,
  `tests/lab02/test_t05_normalization.py`,
  `tests/lab02/smtp_pcap_support.py`, `tests/lab02/reproduce_t03.py`,
  `tests/lab02/test_t03_smtp_mime.py`,
  `tests/lab02/reproduce_t02.py`, `tests/lab02/test_t02_html_entity.py`,
  `tests/lab02/http_pcap_support.py`,
  `tests/lab02/reproduce_t01.py`, `tests/lab02/test_t01_url_decode.py`,
  `tests/lab02/reproduce_http_form.py`, `tests/lab02/test_http_form_pcap.py`,
  `tests/lab02/reproduce_t04.py`, `tests/lab02/test_t04_invalid_bytes.py`,
  `ids/capture/pcap.py`, `ids/capture/live.py`, `ids/parsers/network.py`,
  `ids/parsers/transport.py`, `ids/parsers/application/detector.py`,
  `ids/parsers/application/http.py`, `ids/parsers/application/dns.py`,
  `ids/parsers/application/smtp.py`, `ids/pipeline.py`, `ids/cli.py`,
  `main.py`, các file trong `tests/` và tài liệu trong `TEST/`.
- Người thực hiện có trách nhiệm kiểm tra, chạy thử và hiểu mã nguồn trước khi
  nộp bài.

## Kế hoạch tiếp theo

1. Task 11: flow key/flow_id hai chiều, direction và T08/T11.
2. Tracker counters (T13), TCP handshake/close (T07/T09), UDP (T10) và timeout
   (T12), thực hiện và commit lần lượt.
3. Nối pipeline PCAP/live, config CLI, event/flow output và kiểm tra đủ T01–T14.
4. Kiểm thử traffic thực tế và nghiên cứu TCP stream reassembly cho message
   qua nhiều segment.
