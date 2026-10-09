# T14 — Malformed/unsupported event

## Mục đích và nguồn input

Event invalid/unsupported không làm crash; status/reason phù hợp, policy mark/
skip có hiệu lực, event hợp lệ tiếp theo vẫn được xử lý. Có 23 PacketEvent JSONL
tổng hợp tại boundary sau Parser, chạy qua Decoder rồi Preprocessor. Không phải
PCAP hoặc traffic capture thật; source pcap là mock. Missing required field được
biểu diễn null trong model; đây không phải kiểm thử parser JSON syntax hỏng.

## Scenarios

| Event | Input | Status / quyết định |
|---|---|---|
| 1 | Source IP sai | invalid, skip; normalized IP=null |
| 2 | Destination port=65536 | invalid, skip; normalized port=null |
| 3 | Timestamp sai | invalid, skip; normalized timestamp=null |
| 4 | Network model=null | invalid, skip |
| 5 | Transport model=null | invalid, skip |
| 6 | Source port=null | invalid, skip; không tạo port thay thế |
| 7 | Parser marked malformed | invalid, skip |
| 8 | IPv6 hợp lệ nhưng chưa hỗ trợ | partial, skip kể cả mark |
| 9 | Transport SCTP | partial, skip kể cả mark |
| 10 | Application FTP trên TCP hợp lệ | partial, theo unsupported policy |
| 11 | TTL=256, endpoint còn hợp lệ | partial, theo invalid policy |
| 12 | HTTP target /%ZZ | decode partial; preprocess partial, URI=null, theo invalid policy |
| 13 | DNS answers sai kiểu string | partial, answers=null; theo invalid policy |
| 14 | TCP flag BOGUS | partial, flags=null; skip kể cả mark |
| 15 | Parser marked unsupported | partial, skip kể cả mark |
| 16 | Noninitial IP fragment | partial, skip vì chưa reassembly |
| 17 | Network/transport parser error | partial, skip; endpoint không đáng tin cậy |
| 18 | Application fields sai kiểu list | partial, theo invalid policy |
| 19 | Payload model sai kiểu string | decode error, preprocess partial; theo invalid policy |
| 20 | Application model sai kiểu string | partial, theo invalid policy |
| 21 | TTL sai + application FTP | partial; track chỉ khi cả hai policy mark |
| 22 | Capture source type chưa hỗ trợ | partial, theo unsupported policy |
| 23 | Event hợp lệ sau các event lỗi | valid, track, không còn lỗi/reason |

"skip" trong bảng là action skip_tracking; event vẫn được ghi JSONL với raw,
decoded, normalized, errors và reason. track chỉ là cấp quyền cho Tracker tương
lai, flow vẫn null. mark không sửa status thành valid hoặc bịa endpoint/time.

## Bốn cấu hình đã kiểm thử

| Profile | invalid_event_policy | unsupported_event_policy |
|---|---|---|
| default | skip | mark |
| mark-mark | mark | mark |
| mark-skip | mark | skip |
| skip-skip | skip | skip |

23 × 4 = 92 lượt xử lý event; expected được định nghĩa theo scenario độc lập
với hàm policy. So sánh chính xác status/action/error codes và kiểm tra thêm
normalized field null, reason, raw/decoded preservation và JSONL round-trip.
Required-invalid/unsafe cases luôn skip; mixed optional problems không để mark
của một policy ghi đè skip của policy kia. Event cuối cùng luôn valid/track.

Kết quả thực tế: cả 4 profiles khớp expected, không exception; 92/92 đạt.

## Tái hiện và files

```bash
./venv/bin/python -m tests.lab02.reproduce_t14
./venv/bin/python -m pytest tests/lab02/test_t14_malformed_events.py -v
./venv/bin/python -m pytest -q
```

- input.jsonl: 23 input PacketEvent, giữ cả metadata sai.
- config-{profile}.toml: bốn cấu hình tái hiện.
- expected.json: status/action/error codes cho từng profile và event.
- actual-{profile}.jsonl: bốn output files, mỗi file 23 ProcessedEvent.
- result.txt: script PASS, integration 1 passed, full suite 541 passed.

Có thể dùng --output-dir /tmp/ids-t14 để tái hiện ngoài repo. Hidden-like cases
bool port, naive timestamp, size limits, mixed errors và reprocessing/config
changes còn được unit-test trong tests/lab02/test_preprocessor_policy.py.
Chưa nối main CLI bài 2 hay chạy Flow Tracker; không xác nhận TCP state/counters.
