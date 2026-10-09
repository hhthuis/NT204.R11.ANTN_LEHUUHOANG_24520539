# Task 11 — Bidirectional flow identity và direction

## Mã nguồn

- `ids/flows/tracker.py`: FlowTracker.track(ProcessedEvent), active_flows snapshot,
  export_flows(), remove_flow(key), make_flow_id(key, generation).
- `ids/flows/__init__.py`: mô tả cập nhật phần Tracker đã có.
- `tests/lab02/test_flow_tracker.py`: 53 tests cho flow identity/direction,
  metadata safety, preservation, generations và process-independent IDs.
- `tests/lab02/flow_pcap_support.py`: helper PCAP tổng hợp cho T08/T11, đi qua
  reader/parser/decoder/preprocessor/tracker thật; không sửa main CLI.

## Luồng và hợp đồng

```python
from ids.decoders.decoder import decode_event
from ids.preprocessors.preprocessor import preprocess_event
from ids.flows.tracker import FlowTracker

tracker = FlowTracker()  # dùng cùng instance cho toàn bộ stream
prepared = preprocess_event(decode_event(packet_event))
processed = tracker.track(prepared)
print(processed.flow)
print(tracker.export_flows())
```

Key dùng protocol TCP/UDP và cặp Endpoint(ip, port) từ normalized. FlowKey sort
endpoints để hai chiều lookup cùng key; A/B của record giữ sender/receiver lần
đầu quan sát. A→B forward, B→A backward, không suy đoán client/server bằng port
hay endpoint sort order. Hai endpoint hoàn toàn giống nhau không phân biệt
chiều được bằng 5-tuple; quy ước forward nhất quán.

Event skip_tracking không tạo hoặc sửa active flow. Event track cần valid/partial
status, raw validator eligible và normalized IPv4/TCP/UDP/IP/port/UTC/time/length/
flags hợp lệ. Các policy skip diagnostics được tôn trọng kể cả action bị đổi
thủ công. Metadata lỗi được ghi stage=track/code=tracker_invalid_metadata, action
skip_tracking, flow=null trước insertion; event tiếp theo vẫn xử lý được.
API chỉ nhận ProcessedEvent; object sai loại là programming error TypeError.

Caller event được deepcopy; packet/decoded/normalized/status/preprocess errors
không đổi. Association bất biến và detached. active_flows/export_flows là các
snapshot; không cho caller sửa record nội bộ. Khi retry qua Preprocessor sau
khi sửa input, lỗi tracker cũ được bỏ và reason giữ operator notes/lỗi còn lại.

## flow_id và lifetime

Serialization hash input là compact ASCII JSON array:

```text
["flow-v1", protocol, [low_ip, low_port], [high_ip, high_port], generation]
```

ID = "flow-" + SHA-256 hex đầy đủ, không dùng hash() Python hoặc ghép chuỗi thiếu
delimiter. Generation bắt đầu 1 cho mỗi key. Reverse endpoint, process hashseed,
và thứ tự tạo flow không liên quan không làm đổi ID. Fresh tracker replay cùng
lifetimes tạo cùng IDs; ID này không có capture/session namespace toàn cục.

remove_flow(key) chỉ detach rõ ràng, không phải TCP FIN/RST hay idle timeout.
Tạo lại cùng key trong cùng tracker dùng generation+1, ID mới. Generation history
giữ trong instance; active record đã remove không còn trong active table và các
event cũ vẫn giữ ID/state snapshot của chúng.

## Phạm vi hiện tại

- TCP khởi tạo NEW, UDP state=null. SYN/ACK/FIN/RST chưa chuyển state.
- start_time=last_seen=timestamp của packet đầu tiên; counters/duration hiện
  còn zero. Chưa cập nhật last_seen/counters/application nhận diện muộn: Task 12.
- Chưa automatic close, UDP DNS statistics, expiry/max_active_flows/capacity
  enforcement; các config Tracker sẽ được áp dụng ở task tương ứng.
- Không TCP stream reassembly/TLS và chưa nối main CLI bài 2.
- Không chia phiên mới chỉ vì SYN xuất hiện; lifecycle tasks sẽ quyết định.

## Kiểm thử và evidence

```bash
./venv/bin/python -m pytest tests/lab02/test_flow_tracker.py -v
./venv/bin/python -m pytest -q
```

Kết quả tại commit task: 53 tests mới passed; toàn bộ suite 594 passed.
Log stdout/exit code tại result.txt. T08 và T11 có PCAP/expected/actual/log và
commit riêng sau commit mã nguồn Task 11.
