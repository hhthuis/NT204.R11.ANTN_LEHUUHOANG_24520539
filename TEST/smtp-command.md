# TC-09: SMTP command

## Mục đích

Kiểm tra pipeline nhận diện và parse các SMTP command bắt buộc gồm `HELO`,
`EHLO`, `MAIL FROM` và `RCPT TO`. Các packet sử dụng port đích 2526 để xác
minh application protocol detector có thể nhận diện SMTP từ payload trên port
không chuẩn.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 18/09/2026.
- Script sinh dữ liệu: `tests/generate_smtp_command_pcap.py`.
- PCAP đầu vào: [smtp-command.pcap](smtp-command.pcap).
- JSONL đầu ra: [smtp-command.jsonl](smtp-command.jsonl).
- Client: `10.0.0.10:51000`.
- SMTP server: `10.0.0.25:2526`.
- Số packet: 4.

SMTP payload theo thứ tự packet:

```text
HELO legacy.example.test
EHLO client.example.test
MAIL FROM:<alice@example.test> SIZE=123
RCPT TO:<bob@example.test>
```

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_smtp_command_pcap
python main.py --pcap TEST/smtp-command.pcap --output TEST/smtp-command.jsonl
python -m pytest -v tests/test_smtp_command.py
```

## Kết quả mong đợi

- Cả 4 packet được nhận diện là protocol `SMTP`.
- Message kind của cả 4 packet là `command`.
- `HELO` có domain `legacy.example.test`.
- `EHLO` có domain `client.example.test`.
- `MAIL FROM` có mailbox `alice@example.test` và tham số `SIZE=123`.
- `RCPT TO` có mailbox `bob@example.test`.
- Tất cả message có `message_complete: true`.
- Tất cả event có `parse_status: ok` và `errors` rỗng.

## Kết quả thực tế

Pipeline xử lý đủ 4 packet. Tất cả command, domain, mailbox và tham số được
trích xuất đúng. SMTP được nhận diện thành công trên port 2526 và pytest trả
về `PASSED`.

Log: [smtp-command-result.txt](smtp-command-result.txt).

## Kết luận

Đạt. Pipeline nhận diện và parse thành công các SMTP command bắt buộc trên
port không chuẩn.
