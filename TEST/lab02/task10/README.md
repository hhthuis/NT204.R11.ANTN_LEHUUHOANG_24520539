# Task 10 — Missing/unsupported data và processing policy

## Đã triển khai

- `ids/preprocessors/preprocessor.py`: validation → normalization → policy;
  mỗi lần chạy tính lại status/action/reason, loại diagnostics cũ của chính các
  bước này, giữ raw packet, decoded và ghi chú của caller.
- `ids/preprocessors/policy.py`: áp dụng cấu hình và kiểm tra cả metadata raw
  lẫn normalized trước khi cấp `track`. `flow=null` vì chưa có Tracker runtime.
- `ids/preprocessors/normalization.py`: missing optional collections có defaults
  nhất quán; defaults vẫn chịu giới hạn kích thước và không che lỗi dữ liệu.
- `ids/decoders/decoder.py`: thiếu/wrong-type application hoặc payload không gây
  AttributeError trước khi Preprocessor được chạy. Wrong PacketEvent có decode
  error; optional payload null có skipped. Không catch-all để che lỗi lập trình.
- Config/TOML giải thích mark/skip; unit tests và script T05 cập nhật hợp đồng
  action/defaults. Fixture runner chung phục vụ T06/T14, không phải JSONL CLI.

## Defaults

| Dữ liệu | Missing/null | Malformed hoặc quá giới hạn |
|---|---|---|
| network/transport model, IP, port, timestamp | null; không tạo endpoint/time | null + diagnostics; không tracking |
| application model | null + warning; metadata tốt vẫn track | null + warning; invalid policy áp dụng |
| payload model | null, decode skipped + validation warning | decode error + validation warning; invalid policy áp dụng |
| DNS questions/answers/authorities/additionals | [] | null + diagnostics (item sai có thể null trong list) |
| TCP flags | [] + missing flag warning; không suy đoán state | null + diagnostics; không tracking |
| HTTP/MIME header dictionary | {} | null + diagnostics |
| SMTP commands | [] nếu không có commands hay single command | null + diagnostics |
| UDP flags / optional scalar | null | tùy validator/normalizer, có diagnostics |

Missing được quyết định bằng dữ liệu raw; không dùng phép `value or []` để biến
collection bị lỗi thành empty. Single SMTP command vẫn được giữ khi raw fields
có `command`; commands sai kiểu không bị fallback thành một command khác.
Raw PacketEvent không được sửa bởi defaults. Utility normalize_flags(None)
vẫn trả None; adapter normalize_packet mới áp dụng default có ngữ cảnh.

## Chính sách

| Vấn đề | mark | skip |
|---|---|---|
| Required data invalid / malformed packet | invalid, skip_tracking | invalid, skip_tracking |
| Optional data malformed hoặc normalization lỗi | partial, track nếu metadata an toàn | partial, skip_tracking |
| Unsupported application/source/URI form | partial, track nếu metadata an toàn | partial, skip_tracking |
| Unsupported network/transport/parser packet hoặc noninitial fragment | partial, skip_tracking | partial, skip_tracking |

`invalid_event_policy` áp dụng invalid-data diagnostics của Preprocessor, gồm
cả lỗi optional/normalization trên event partial. `unsupported_event_policy`
áp dụng unsupported-data diagnostics. Khi có cả hai loại, bất kỳ policy skip
nào cũng chặn tracking. Cả mark và skip đều giữ event trong output để ghi log;
skip nghĩa là skip tracking, không xóa event hoặc bỏ dòng JSONL.

Missing application/payload/flags, duplicate flags đã sửa representation và
parser partial warning không tự kích hoạt invalid policy. Wrong-type model
khác model null và được coi là malformed. UNKNOWN application được hỗ trợ.
Decode errors giữ nguyên và không tự kích hoạt preprocess policy; metadata
TCP/UDP tốt vẫn có thể được cấp track. Parser errors network/transport luôn
chặn; partial ở application không tự làm mất endpoint đáng tin cậy.

`track` chỉ được cấp khi validator eligible, normalized timestamp có UTC,
network IPv4 với hai IP hợp lệ, transport TCP/UDP với integer ports 0..65535,
captured_length hợp lệ và TCP flags có list dùng được. Normalization limit làm
mất field bắt buộc thì skip kể cả mark. Flags thiếu trở thành [] không cho phép
Tracker suy đoán handshake/state. Không tạo flow ở bước này.

Errors policy có stage=preprocess, prefix policy_; reason giữ lỗi decode,
validation, normalization và quyết định policy. Rerun thay policy hoặc sửa raw
data phải bỏ các diagnostics/reason cũ đã hết. Status không bị đổi thành valid
chỉ vì mark; invalid luôn còn invalid.

## API và tái hiện

```python
from ids.config import load_config
from ids.decoders.decoder import decode_event
from ids.preprocessors.preprocessor import preprocess_event

config = load_config("config/default.toml")
result = preprocess_event(decode_event(packet, config.decoder), config.preprocessor)
print(result.preprocess_status, result.processing_action, result.reason)
```

```bash
./venv/bin/python -m pytest tests/lab02/test_preprocessor_policy.py -v
./venv/bin/python -m tests.lab02.reproduce_t05 --output-dir /tmp/ids-task10-t05
./venv/bin/python -m pytest -q
```

Kết quả tại commit task: 74 tests mới passed; regression T05 PASS; full suite
539 passed. stdout/exit code tại result.txt. T06 và T14 có test/artifacts và
commit riêng sau commit mã nguồn này.

## Phạm vi

Preprocessor hoàn thiện API bài 2; main.py/CLI vẫn chỉ chạy parser bài 1.
Chưa flow table/state/counters/timeout hay CLI output event/flow của bài 2.
Fixture JSONL dùng model đã có và dữ liệu tương thích JSON; không phải reader
production hỗ trợ mọi JSON bị hỏng hoặc kiểm thử capture mạng thật.
