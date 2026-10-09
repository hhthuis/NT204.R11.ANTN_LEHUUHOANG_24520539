# T05 — Normalization

Ngày kiểm thử: 09/10/2026.

## Yêu cầu và input

Header/protocol/domain khác cách viết phải có representation nhất quán sau
Preprocessor. Input là JSONL PacketEvent fixture, được tạo ở boundary sau parser
để giữ được những biến thể format mà parser Scapy thường đã chuẩn hóa trước.
Đây là metadata tổng hợp, không phải traffic thật hoặc PCAP đã capture. Bài yêu
cầu test input/script tái hiện được; case này không cần một PCAP thay cho event
fixture. Test HTTP byte pipeline với packet Scapy đã có trong unit tests Task 09.

## Luồng chạy

```text
input.jsonl → PacketEvent models → decode_event
  → preprocess_event → validate_event → normalize_packet → actual.jsonl
```

Script lưu input đầy đủ, gồm dữ liệu raw kiểu chữ ban đầu và metadata source/
packet_id. Source type=pcap là capture-source mock; không có file capture tương
ứng. Decoder vẫn chạy trước Preprocessor, normalized không lấy decoded URI làm
nguồn hoặc ghi đè decoded fields. Mỗi cặp gồm hai định dạng của cùng metadata.

## Mong đợi và kết quả thực tế

| Events | Biến thể input | Expected normalized |
|---|---|---|
| 1/2 — HTTP | ipv4/tcp/http khác case và whitespace; get/GET; header khác case, string/list và case collision; percent hex khác case | IPv4/TCP/HTTP/GET; lowercase header keys, list values giữ thứ tự; /Admin%2FA?q=x+y&x=%252f |
| 3/4 — DNS | udp/dns, Example.COM. và example.com; a/A, in/IN, cname/CNAME; domain RR khác case | UDP/DNS, example.com, A/IN/CNAME, target.example.com |
| 5/6 — SMTP EHLO | smtp/SMTP, ehlo/EHLO, Client.Example.COM. và client.example.com | SMTP/EHLO/client.example.com |
| 7/8 — SMTP mailbox | mail from/MAIL FROM, Alice@Example.COM. và Alice@example.com | MAIL FROM, Alice@example.com; giữ chữ A local-part |
| 9 — Lỗi timestamp | not-a-timestamp | invalid, normalized.timestamp=null, validation và normalization reasons |
| 10 — Event tiếp theo | Metadata TCP hợp lệ | valid, tiếp tục xử lý |

Events 1–8 còn kiểm tra timestamp +07:00/UTC thành cùng giá trị UTC microsecond
Z; IP có outer whitespace thành canonical IPv4; TCP flag list khác case/thứ tự
thành PSH/ACK theo bit order. UDP flags=null, không tự đặt TCP state.

Thực tế trùng expected.json cho toàn bộ 10 event. Bốn cặp có toàn bộ normalized
giống nhau; raw và decoded giữ nguyên. HTTP X-Token/x-token giữ ["AbC", "DeF"],
không overwrite/casefold value. Case HTTP path /Admin giữ nguyên, encoded slash
không thành slash ở normalized URI, + trong query giữ nguyên và %252f không được
decode thêm. Decoded URI riêng của Task 05 có thể chứa /Admin/A và %2f; không
được dùng để thay normalized target lấy từ raw.

## Files bằng chứng

- input.jsonl: 10 PacketEvent đầu vào, gồm mọi field model.
- expected.json: status, toàn bộ normalized và error codes mong đợi.
- actual.jsonl: 10 ProcessedEvent thực tế, có packet/decoded/normalized/metadata.
- result.txt: stdout/exit code script, pytest T05 và full suite.

## Tái hiện

```bash
./venv/bin/python -m tests.lab02.reproduce_t05
./venv/bin/python -m pytest tests/lab02/test_t05_normalization.py -v
./venv/bin/python -m pytest -q
```

Script tạo lại input/expected/actual, so sánh expected và raw preservation trước
khi báo PASS. Dùng --output-dir /tmp/ids-t05 nếu muốn output ngoài repo.
Integration test đọc lại JSONL, xác nhận decoded view không đổi, kết quả của
mỗi cặp, URI/header/mailbox semantics và event 10 xử lý sau event 9 lỗi.

Kết quả: T05 PASS, pytest 1 passed; toàn bộ suite 465 passed. Log tại result.txt.

## Phạm vi

Task 09 chưa áp dụng mark/skip policy hoặc missing-field defaults đầy đủ;
processing_action vẫn skip_tracking và flow null. Main CLI chưa gọi pipeline
bài 2. Chưa TCP tracking, full URI resolution/Unicode domain remapping hoặc
TCP reassembly. T06/T14 sẽ có test case/artifact riêng ở Task 10.
