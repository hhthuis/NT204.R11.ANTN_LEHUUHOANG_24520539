# Bài 3 — Giai đoạn 1, Task 01: Model và phạm vi

## 1. Phạm vi của task này

Định nghĩa Rule và các điều kiện, EngineInput, FlowContext, MatchResult,
DetectionEvent; ghi rõ cú pháp hỗ trợ và policy lỗi. Mã tại
[ids/engine/models.py](../ids/engine/models.py).

**Chưa thực hiện:** config loader, adapter, suy luận role, rule loader/parser/
validator/indexer, matcher, evaluator, detection generator hay nối CLI/pipeline.
Task này không hoàn thành case nào trong TC01–TC14. Tên các keyword dưới đây
là phạm vi sẽ triển khai ở task tương ứng, không phải tính năng hiện đã chạy.

## 2. Các model và quan hệ

```text
RuleHeader + Content/Flow/Flags/SizeCondition → Rule

ProcessedEvent bài 2 + FlowContext + buffers → EngineInput
Rule + EngineInput → Matching Engine sau này → MatchResult
Rule + EngineInput + MatchResult → Generator sau này → DetectionEvent
```

| Model | Vai trò |
|---|---|
| PortRange | Port đơn khi start=end; range inclusive; None ở header là any |
| RuleHeader | Action, protocol, IP/port nguồn/đích và direction |
| ContentCondition | Pattern bytes, buffer và các modifier của riêng content đó |
| FlowCondition | Chiều client/server và yêu cầu established/not_established |
| FlagsCondition | Tập TCP flags, mode so khớp và tập flags bỏ qua |
| SizeCondition | Toán tử dsize, giá trị và upper bound nếu có |
| Rule | Header, metadata và các điều kiện; giữ nguyên thứ tự contents |
| FlowContext | Snapshot FlowRecord, direction, establishment và role evidence |
| EngineInput | ProcessedEvent, context và dictionary tên buffer → bytes |
| ContentMatch | Content nào, buffer nào, pattern và span byte [start,end) |
| MatchResult | SID/rev, MATCH/NO_MATCH/SKIPPED, bằng chứng và reason |
| DetectionEvent | Timestamp, SID/rev/msg, 5-tuple, ứng dụng, flow và match info |

Engine dùng lại ProcessedEvent, Endpoint, FlowRecord, FlowDirection và
FlowProtocol của bài 2. Không tạo phiên bản thay thế cho những model này;
không import Scapy. FlowContext/EngineInput sao chép dữ liệu lồng để không sửa
nhầm event hoặc flow của bên gọi. Đây không phải các lớp thuật toán.

Type hints mô tả hợp đồng, **không tự validate mọi giá trị**. Parser & Validator
ở task sau kiểm tra cú pháp, range và tổ hợp điều kiện; Adapter kiểm tra dữ liệu
đầu vào. Không xem việc dựng được dataclass là chứng minh rule text valid.

## 3. Cú pháp sẽ hỗ trợ

| Nhóm | Phạm vi |
|---|---|
| Action | alert |
| Protocol | tcp, udp; thêm ip/any theo ghi chú TC06 dưới đây |
| IP | any, IPv4 đơn, IPv4 CIDR |
| Port | any, single, range start:end inclusive; range mở dùng 0/65535 |
| Direction | ->, <>; chiều đảo đổi cả IP và port |
| Identification | msg, sid, rev bắt buộc |
| Content | Positive content; ASCII, escape, hex trong pipe và mixed ASCII/hex |
| Modifiers | nocase, offset, depth, distance, within |
| Packet/TCP | flags, dsize |
| Flow | to_server, to_client, established, not_established |
| Classification | classtype, priority tùy chọn |

Hỗ trợ cách viết modifier riêng (`content:"ABC"; nocase; offset:0;`) và inline
(`content:"ABC",nocase,offset 0;`), cùng chuyển về ContentCondition. Parser sau
này phải hiểu quotes/escape, không split(';') hoặc cắt comment bên trong chuỗi.

Mục 3 PDF chỉ nêu TCP/UDP nhưng TC06 nhắc IP/TCP/UDP/any. Chốt cho dự án:
`ip` là nhóm chung cho đầu vào IPv4 TCP/UDP đang hỗ trợ; protocol `any` là alias
mở rộng riêng cho TC06. **Protocol any không được coi là cú pháp Snort chuẩn**;
khác với any ở vị trí IP/port. Chưa mở rộng capture/tracker sang ICMP/IPv6.

Không bắt buộc và chưa hỗ trợ: pcre, byte_test/byte_jump, file inspection, TLS,
Lua/plugin, flowbits, negated content, sticky buffers, biến mạng và toàn bộ
cú pháp Snort. Không tự bỏ keyword lạ rồi đánh giá phần rule còn lại.

## 4. Hợp đồng dữ liệu để matcher dùng sau này

- Mặc định content tìm trong buffer `payload`: bytes đầy đủ khôi phục từ raw
  payload của event bài 2; không dùng preview hoặc chuỗi Base64 làm nội dung.
- Model cho phép buffer có tên khác để mở rộng sau; baseline chưa tự match
  decoded URI/body và chưa hỗ trợ sticky buffer keyword.
- Offset/depth tính từ đầu buffer; distance/within tính tương đối với content
  trước trong cùng buffer. Không trộn hai nhóm modifier trên một content.
- Nội dung không có positional modifier được tìm từ đầu buffer. Giữ thứ tự
  content; khi relative matching phải xét các occurrence cần thiết, không mặc
  định chỉ chọn lần xuất hiện đầu.
- Nocase dùng ASCII bytes; offsets theo byte, không theo số ký tự Unicode.
- Dsize dùng packet.payload.length, không dùng captured_length hoặc flow.byte_count.
- FlagsCondition giữ tên flags như dữ liệu normalized: SYN, ACK, FIN, RST...
  Mode exact mặc định; + → all, * → any, ! → none; hỗ trợ ignore mask và flags:0.
- Dsize gồm =, !, <, <=, >, >=, <> exclusive và <=> inclusive, giá trị 0..65535.
- FlowContext.direction là forward/backward. Không tự coi forward là to_server.
  Client/server chưa biết dùng None; role_reason giải thích khi đã xác định.
- Context.established=True/False/None là đã biết established/đã biết chưa
  established/chưa xác định. Khác FlowCondition.established=None: không ràng buộc.
- Context phải ứng với packet hiện tại, không dùng state/counters cuối phiên
  để đánh giá packet trước đó. Cách lấy snapshot và xác định role thuộc Task 02.
- Không có key payload trong buffers khác key payload có giá trị b"".
- DetectionEvent.src/dst là Endpoint chứa IP/port. priority/classtype/flow_id
  có thể null khi chưa có giá trị. Không tạo flow ID giả.
- Matcher không in cảnh báo. Một event được phép match nhiều rule. Detection
  generator ở task sau chỉ dựng DetectionEvent từ match thành công.

## 5. Policy lỗi và trạng thái

| Trường hợp | Policy cho module sẽ triển khai |
|---|---|
| Rule đúng và thuộc subset | valid, đưa vào repository nếu được bật |
| Rule sai cú pháp/kiểu/range/thiếu field bắt buộc | invalid, ghi source/code/reason; tiếp tục rule khác |
| Keyword hoặc feature ngoài subset | unsupported, ghi source/keyword/reason; không kích hoạt rule |
| Header/content không thỏa | NO_MATCH |
| Thỏa tất cả điều kiện | MATCH, kèm match information |
| Thiếu buffer/context cần thiết hoặc hết giới hạn xử lý | SKIPPED, có reason; không tạo DetectionEvent |
| Metadata bắt buộc của event unsafe | Bỏ qua evaluation event và ghi diagnostic |
| Không mở được file/config hoặc ghi output thất bại | Báo lỗi vận hành, không báo phiên chạy thành công |

Không đồng nhất skip_tracking của bài 2 với bỏ tất cả rule; rule không cần flow
có thể đánh giá nếu metadata cần thiết vẫn an toàn. Flow/context chưa biết không
được coi là bằng chứng not_established hoặc to_server.

Chốt policy SID trùng cho repository sau này: trong các rule valid và được bật,
giữ rev cao nhất; nếu cùng SID/rev, giữ bản xuất hiện trước và báo duplicate.
Rule invalid/unsupported không ghi đè bản valid. Enable/disable và giới hạn
kích thước/chi phí sẽ cấu hình ở task cấu hình/loader, chưa viết trong Task 01.

## 6. Export và kiểm tra model

Model có to_dict(): enum thành string, tuple thành array, bytes thành object
Base64+length, datetime có timezone thành UTC microsecond Z. Timestamp thiếu
timezone bị từ chối khi export. Field đơn thiếu dùng null, collections dùng []/{}.
Export tạo dữ liệu tách biệt; FlowRecord dùng exporter bài 2 để giữ duration.

Kiểm tra riêng hợp đồng bằng:

```bash
./venv/bin/python -m pytest tests/bt3/test_models.py -v
```

Các test này không chạy parser, không tìm content và không chứng minh Detection
Generator đã hoạt động. Formal TC01–TC14 sẽ có kết quả riêng ở TEST/BT3/ khi làm
đến module tương ứng.

## Nguồn đối chiếu

- [PDF bài 3](../Bai-tap-03_Core_Engine_IDS.pdf).
- [Snort content](https://docs.snort.org/rules/options/payload/content),
  [positional modifiers](https://docs.snort.org/rules/options/payload/oddw).
- [Snort flow](https://docs.snort.org/rules/options/non_payload/flow),
  [flags](https://docs.snort.org/rules/options/non_payload/flags),
  [dsize](https://docs.snort.org/rules/options/payload/dsize).
- [Snort protocol header](https://docs.snort.org/rules/headers/protocols):
  căn cứ để tách alias protocol any của dự án khỏi cú pháp Snort chuẩn.
