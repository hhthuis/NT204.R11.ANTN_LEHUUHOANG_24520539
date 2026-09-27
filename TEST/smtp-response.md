# TC-10: SMTP response

## Mục đích

Kiểm tra pipeline nhận diện và parse SMTP response, bao gồm các status code
`220`, `250`, `354`, `550` và response nhiều dòng. Test xác nhận parser lấy
đúng status code, message, danh sách message và trạng thái hoàn chỉnh.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 27/09/2026.
- Script sinh dữ liệu: `tests/generate_smtp_response_pcap.py`.
- PCAP đầu vào: [smtp-response.pcap](smtp-response.pcap).
- JSONL đầu ra: [smtp-response.jsonl](smtp-response.jsonl).
- SMTP server: `10.0.0.25:25`.
- Client: `10.0.0.10:51000`.
- Số packet: 4.

SMTP payload theo thứ tự packet:

```text
220 mail.example.test ESMTP ready

250-mail.example.test
250-PIPELINING
250 STARTTLS

354 End data with <CR><LF>.<CR><LF>

550 5.1.1 Mailbox unavailable
```

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_smtp_response_pcap
python main.py --pcap TEST/smtp-response.pcap --output TEST/smtp-response.jsonl
python -m pytest -v tests/test_smtp_response.py
```

## Kết quả mong đợi

- Cả 4 packet được nhận diện là protocol `SMTP`.
- Message kind của cả 4 packet là `response`.
- Các status code lần lượt là `220`, `250`, `354`, `550`.
- Response `250` được nhận diện là multiline response.
- Response `250` chứa ba message: hostname, `PIPELINING`, `STARTTLS`.
- Các response còn lại được nhận diện là single-line response.
- Tất cả message có `message_complete: true`.
- Tất cả event có `parse_status: ok` và `errors` rỗng.

## Kết quả thực tế

Pipeline xử lý đủ 4 packet và trích xuất đúng tất cả status code. Multiline
response `250` được gom thành một response hoàn chỉnh với ba message. Pytest
trả về `PASSED`.

Log: [smtp-response-result.txt](smtp-response-result.txt).

## Kết luận

Đạt. Pipeline nhận diện và parse thành công SMTP single-line và multiline
response.
