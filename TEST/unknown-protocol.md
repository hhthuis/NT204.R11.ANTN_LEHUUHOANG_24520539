# TC-11: Unknown protocol

## Mục đích

Kiểm tra pipeline không bị crash khi TCP hoặc UDP payload không thuộc HTTP,
DNS hay SMTP. Test cũng xác nhận port phổ biến chỉ là tín hiệu nhận diện và
không tự động quyết định application protocol khi payload không hợp lệ.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 27/09/2026.
- Script sinh dữ liệu: `tests/generate_unknown_protocol_pcap.py`.
- PCAP đầu vào: [unknown-protocol.pcap](unknown-protocol.pcap).
- JSONL đầu ra: [unknown-protocol.jsonl](unknown-protocol.jsonl).
- Số packet: 3.

Các packet kiểm thử:

1. TCP `10.0.0.11:52000 → 10.0.0.20:9999`, payload text của một protocol
   tùy ý.
2. UDP `10.0.0.12:53000 → 10.0.0.20:9999`, payload chứa dữ liệu nhị phân và
   byte không hợp lệ theo UTF-8.
3. TCP `10.0.0.13:52001 → 10.0.0.20:80`, payload không có HTTP request line
   hợp lệ dù destination port là 80.

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_unknown_protocol_pcap
python main.py --pcap TEST/unknown-protocol.pcap --output TEST/unknown-protocol.jsonl
python -m pytest -v tests/test_unknown_protocol.py
```

## Kết quả mong đợi

- Pipeline xử lý đủ 3 packet và không phát sinh exception.
- Network và transport information vẫn được trích xuất.
- Payload vẫn được lưu dưới dạng Base64 và text preview.
- Application protocol của cả 3 packet là `UNKNOWN`.
- Application `kind` là `null` và `fields` là object rỗng.
- Packet gửi đến port 80 không bị nhận diện sai là HTTP.
- Tất cả event có `parse_status: ok` và `errors` rỗng.

## Kết quả thực tế

Pipeline xử lý đủ 3 packet. Cả TCP, UDP và TCP trên port 80 đều được đánh
dấu `UNKNOWN`. Dữ liệu network, transport và payload vẫn được giữ trong
event. Pytest trả về `PASSED`.

Log: [unknown-protocol-result.txt](unknown-protocol-result.txt).

## Kết luận

Đạt. Unknown application protocol không làm pipeline dừng và không gây nhận
diện sai dựa riêng trên port.
