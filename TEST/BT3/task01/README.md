# Bài 3 — Giai đoạn 1, Task 01: Model và phạm vi

Chỉ định nghĩa hợp đồng dữ liệu trong ids/engine/models.py và chốt phạm vi /
policy lỗi tại [docs/BT3_SCOPE.md](../../../docs/BT3_SCOPE.md). Không có config,
adapter, parser, matching algorithm hoặc tích hợp pipeline/CLI trong task này.

5 kiểm thử trong tests/bt3/test_models.py xác minh:

1. Rule giữ header, thứ tự điều kiện và pattern nhị phân khi export JSON.
2. EngineInput/FlowContext dùng lại model bài 2, sao chép snapshot để không chia sẻ dữ liệu.
3. Buffers mặc định độc lập; thiếu payload khác payload rỗng; unknown context không bị ép False.
4. DetectionEvent mẫu ghi được bằng JsonlWriter, giữ metadata, bytes và timestamp UTC.
5. Timestamp thiếu timezone không bị đoán ngầm khi export.

DetectionEvent trong test được dựng bằng model, không phải phát hiện do engine
sinh ra. Đây là kiểm thử hợp đồng, **không phải TC14**. TC01–TC14 hiện **0/14**.

```bash
./venv/bin/python -m pytest tests/bt3/test_models.py -v
./venv/bin/python -m pytest -q
```

Ngày kiểm tra: 25/10/2026. Lệnh, stdout/stderr và exit code lưu trong result.txt.
Kết quả: 5 kiểm thử hợp đồng passed, toàn bộ suite 843 passed; cả hai exit code 0.
