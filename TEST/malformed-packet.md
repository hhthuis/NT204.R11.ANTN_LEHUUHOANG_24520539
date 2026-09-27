# TC-12: Malformed packet

## Mục đích

Kiểm tra pipeline không bị dừng khi gặp packet bị cắt ngắn, thiếu header hoặc
có application payload sai định dạng. Test bao phủ lỗi tại network,
transport, HTTP và SMTP.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 27/09/2026.
- Script sinh dữ liệu: `tests/generate_malformed_packet_pcap.py`.
- PCAP đầu vào: [malformed-packet.pcap](malformed-packet.pcap).
- JSONL đầu ra: [malformed-packet.jsonl](malformed-packet.jsonl).
- Số packet: 4.

Các packet kiểm thử:

1. Ethernet frame khai báo EtherType IPv4 nhưng IPv4 header chỉ có 8 byte.
2. IPv4 packet khai báo protocol TCP nhưng chỉ có 4 byte của TCP header.
3. HTTP request có start line hợp lệ nhưng header `Malformed header` không có
   dấu hai chấm.
4. SMTP `EHLO` command thiếu `CRLF` kết thúc dòng.

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_malformed_packet_pcap
python main.py --pcap TEST/malformed-packet.pcap --output TEST/malformed-packet.jsonl
python -m pytest -v tests/test_malformed_packet.py
```

## Kết quả mong đợi

- Pipeline xử lý đủ 4 packet và ghi đủ 4 JSONL event.
- IPv4 header bị cắt được đánh dấu `malformed`, lỗi ở stage `network`.
- TCP header bị thiếu được đánh dấu `malformed`, lỗi ở stage `transport`.
- HTTP header sai được đánh dấu `partial`, lỗi ở stage `http`.
- SMTP command thiếu line terminator được đánh dấu `partial`, lỗi ở stage
  `smtp`.
- Pipeline tiếp tục xử lý packet kế tiếp sau mỗi packet lỗi.
- CLI kết thúc bình thường, không có unhandled exception.

## Kết quả thực tế

Pipeline xử lý đủ 4 packet và ghi đúng lỗi tương ứng cho từng tầng. Packet
HTTP và SMTP vẫn giữ network, transport và payload đã parse được. Pytest trả
về `PASSED`.

Log: [malformed-packet-result.txt](malformed-packet-result.txt).

## Kết luận

Đạt. Malformed packet không làm pipeline dừng và mỗi lỗi được ghi vào
`parse_status` cùng danh sách `errors`.
