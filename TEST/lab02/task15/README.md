# Task 15 — UDP DNS flow tracking

## Công việc thực hiện

DNS parser, normalizer, bidirectional UDP lookup và statistics đã có từ các
task trước; kiểm thử wire packets mới xác nhận chúng hoạt động xuyên pipeline.
Không thêm UDP tracker riêng, không đổi ids/ production modules ở task này.

- tests/lab02/udp_dns_support.py: make_dns_packet() tạo Ethernet/IPv4/UDP với
  DNS query hoặc response A; DNS bytes nằm trong Raw, explicit MAC không dùng
  raw socket. prepare_packet() reload bytes rồi Parser → Decoder → Preprocessor.
  Timestamp Decimal UTC microseconds. Fixture cho phép changed endpoints/port,
  transaction ID/domain, name compression và payload empty/unknown.
- tests/lab02/test_udp_dns_flow.py: 19 tests bổ sung cho tracker trên dữ liệu
  đã parse, không tự gán ApplicationInfo("DNS") để thay bước DNS parsing.
- README cập nhật scope, kết quả, kế hoạch và khai báo hỗ trợ AI.

## Quy tắc đã xác nhận

1. Client 10.0.0.2:53000 ↔ resolver 10.0.0.1:53 thuộc một UDP flow. Query
   forward, response backward khi query được quan sát đầu tiên; nếu response
   đứng đầu thì server là endpoint A và response forward, query backward.
2. Transport UDP, application DNS, state=null; SYN/ACK/FIN/RST counters đều0.
   UDP không tạo TCP handshake/close context hoặc gọi TCP state handlers.
3. Một flow theo bidirectional 5-tuple, không theo DNS transaction ID/domain.
   Nhiều transaction IDs hoặc query domains trên cùng tuple vẫn cùng lifetime.
   Retransmission giữ identity và tính thêm packet/bytes mỗi observation.
4. Thay client IP, server IP, client port hoặc server port tách flow; reverse
   response được gắn đúng flow của nó. TCP DNS với cùng endpoints tách khỏi UDP.
5. Bytes dùng captured_length gồm 14-byte Ethernet, 20-byte IPv4, 8-byte UDP
   và DNS payload, không chỉ payload.length. Query Example.Test A có payload
   30/captured72; response A uncompressed có payload58/captured100, totals172.
   Forward/backward=1/72 và 1/100; duration=0.2s. Compressed answer name dùng
   pointer2 bytes thay name14 bytes, response captured88, totals160.
6. Raw query/answer names giữ Example.Test; normalized names example.test.
   Answer A=192.0.2.10, TTL300, query type A được giữ đúng. Original wire name
   có dấu chấm cuối; parser đã bỏ dấu chấm khi tạo raw PacketEvent, normalizer
   không sửa raw PacketEvent thêm lần nữa.
7. Empty/unknown UDP vẫn track khi metadata hợp lệ; UNKNOWN app nâng lên DNS
   khi packet DNS xuất hiện và không downgrade khi lại gặp unknown/empty.
8. Skip/bad metadata không đổi flow statistics/context. Fault injection lỗi
   statistics ở flow mới hoặc flow sẵn có không tăng dở generation/counters;
   observation hợp lệ tiếp theo vẫn được xử lý. Caller và các views giữ nguyên.

## Chẩn đoán binary payload

DNS response hợp lệ có binary header/answer không phải UTF-8 text. DNS parser
đọc đúng, parse_status=ok và packet.errors=[]; generic character decoder hiện
vẫn thử UTF-8, tạo decode_status=partial và invalid_character_sequence ở stage
decode. Preprocessor metadata vẫn valid và action track. Tracker bảo toàn
chẩn đoán/reason/decoded view và raw Base64, không làm flow mất DNS label.

Trong fixture response cơ bản, reason là:
Invalid utf-8 sequence at bytes 2:3: invalid start byte.
Đây không phải kết luận DNS message malformed. Decoder policy/dispatch hiện có
được giữ nguyên; không dùng character view để thay DNS wire parse hoặc flow key.

## Lệnh và kết quả

```bash
./venv/bin/python -m pytest tests/lab02/test_udp_dns_flow.py -v
./venv/bin/python -m tests.lab02.reproduce_t07 --output-dir /tmp/ids-task15-t07
./venv/bin/python -m tests.lab02.reproduce_t08 --output-dir /tmp/ids-task15-t08
./venv/bin/python -m tests.lab02.reproduce_t09 --output-dir /tmp/ids-task15-t09
./venv/bin/python -m tests.lab02.reproduce_t11 --output-dir /tmp/ids-task15-t11
./venv/bin/python -m tests.lab02.reproduce_t13 --output-dir /tmp/ids-task15-t13
./venv/bin/python -m pytest -q
```

19 new tests passed; T07/T08/T09/T11/T13 PASS; full suite 771 passed tại source
commit. result.txt lưu stdout/exit code thực tế. Không ghi đè artifacts lịch
sử của các case trước; regression chạy /tmp. T10 sẽ có PCAP/config/expected/
actual/flow snapshots/README/log và commit riêng sau phần task này.

## Giới hạn

Task 15 kiểm tra UDP/DNS hai chiều và statistics. Chưa idle timeout/capacity/
queue bounds (Task 16), main CLI bài 2 (Task 17), DNS transaction correlation
engine hoặc IP fragment reassembly. Name compression có test; fixture không
có EDNS OPT và không dùng kết quả này để khẳng định mọi DNS resource-record
variant được hỗ trợ. Không phải capture traffic mạng thật.
