# Kiểm thử bổ sung — HTTP form decoding

Ngày kiểm thử: 09/10/2026.

## Mục đích

PDF yêu cầu decode application/x-www-form-urlencoded dù không đặt một T ID
riêng cho chức năng này. Case bổ sung kiểm chứng bằng PCAP và JSONL đầu ra.

## Input và kết quả mong đợi/thực tế

PCAP có 7 HTTP POST request, mỗi request đầy đủ trong một packet. URI /submit
và raw body/payload được giữ nguyên; decoder chỉ ghi kết quả riêng.

| Packet | Nội dung | Kết quả thực tế |
|---|---|---|
| 1 | tag lặp, Alice+Bob, %2B, a%26b%3Dc, blank value | ok; tag=[one,two], name=[Alice Bob], plus=[+], data=[a&b=c], blank=[""] |
| 2 | UTF-8 name/value, quoted UTF8 charset, %252B | ok; café=[Việt Nam], once=[%2B] |
| 3 | q=%ZZ | partial, giữ literal %ZZ, có lỗi/reason |
| 4 | q chứa byte 0xff | partial theo replace, giữ raw byte, text có U+FFFD |
| 5 | q=next sau các packet lỗi | ok, không lỗi |
| 6 | q=a+b nhưng Content-Type text/plain | Không chạy form decoder, form=null |
| 7 | Body rỗng, form Content-Type | ok, parameters={} |

Packet 1 xác nhận tách delimiter trước decode và giữ đúng giá trị lặp. Packet 2
xác nhận decode đúng một lần. Kiểm thử unit còn kiểm tra strict byte policy và
giới hạn input/output; xem `tests/lab02/test_decoder_http.py`.

## Files

- `input.pcap`: packet đầu vào có timestamp cố định.
- `expected.json`: summary mong đợi cho 7 packet.
- `actual.jsonl`: 7 ProcessedEvent thực tế.
- `result.txt`: log tái hiện, pytest và toàn bộ suite.

## Lệnh tái hiện

```bash
./venv/bin/python -m tests.lab02.reproduce_http_form
./venv/bin/python -m pytest tests/lab02/test_http_form_pcap.py -v
```

Script tạo input, expected và actual, so sánh trước khi báo PASS. Có thể dùng
`--output-dir /tmp/ids-http-form` để xuất sang thư mục khác.

## Kết quả thực tế

- Script: HTTP form PASS, đủ 7 events.
- Pytest case: 1 passed; raw body Base64/payload byte giữ nguyên trong output.
- Toàn bộ suite sau Task 05, T01 và form case: 187 passed.
- Kết quả kiểm thử form: PASS.

Pipeline của script: PCAP reader → parser bài 1 → HTTP decoder → JSONL.
Main CLI chưa được nối decoder. Chưa preprocess/track/TCP reassembly hoặc
decode HTTP chunked body. Đây là kiểm thử form bổ sung, không tăng số T-case
bắt buộc; hiện các T-case bài 2 hoàn thành là T01 và T04.
