# Task 01 — Model kết quả xử lý event

Ngày kiểm thử: 09/10/2026.

## Mục đích

Định nghĩa hợp đồng dữ liệu cho Decoder, Preprocessor và Flow Tracker của
bài tập 2, dựa trên `PacketEvent` của bài tập 1. Model không gọi parser,
không bắt packet và chưa thực hiện decode/normalize/track.

## Input và output

- Input: `PacketEvent` tổng hợp trong `tests/lab02/test_processing_models.py`.
- Output: `ProcessedEvent.to_dict()` được serialize và đọc lại bằng `json`.
- Raw payload có byte `0xff` được giữ trong Base64; URI percent-encoded được
  giữ trong `packet.application.fields.target`.
- Decoded/normalized values trong test được điền thủ công để kiểm tra hợp đồng
  lưu trữ, không phải kết quả chạy Decoder hay Preprocessor.
- Chưa có PCAP/JSONL từ pipeline bài 2 ở task này. T01–T14 sẽ có bằng chứng
  riêng khi triển khai các module tương ứng.

## Cách chạy

```bash
./venv/bin/python -m pytest tests/lab02/test_processing_models.py -v
./venv/bin/python -m pytest -q
```

## Kết quả mong đợi

1. Event chưa xử lý serialize được, các field thiếu là `null` hoặc collection
   rỗng phù hợp; chưa được cho phép tracking.
2. Enum status/action/stage serialize thành chuỗi. Text tiếng Việt, URI raw,
   decoded URI và Base64 byte gốc được giữ đúng sau JSON round-trip.
3. Mỗi event có packet snapshot và collections riêng; sửa event thứ nhất không
   ảnh hưởng event thứ hai hoặc `PacketEvent` đầu vào.
4. Sửa dictionary xuất bởi `to_dict()` không ảnh hưởng dữ liệu trong event.
5. Các test bài 1 tiếp tục pass.

## Kết quả thực tế

- Model tests: 4 passed.
- Toàn bộ test suite: 66 passed (62 test hiện có và 4 test model mới).
- Log được lưu tại `result.txt` trong cùng thư mục.
- Kết quả Task 01: PASS.

## Quy ước dữ liệu

- `packet`: bản sao sâu của event gốc; các bước xử lý ghi field riêng.
- `decoded`/`normalized`: dictionary chỉ chứa giá trị tương thích JSON.
- Byte nhị phân: Base64; không đưa Scapy packet hoặc `bytes` trực tiếp vào JSON.
- `decode_status`: `ok`, `partial`, `error`, `skipped`.
- `preprocess_status`: `valid`, `partial`, `invalid`; `null` trước validation.
- `processing_action`: `track` hoặc `skip_tracking`; mặc định `skip_tracking`.
- `reason`: chuỗi hoặc `null`; stage thực thi cần cung cấp lý do khi cần.
- `errors`: danh sách `stage`, `code`, `message`; không trộn vào lỗi parser gốc.
- `flow`: `null` trước tracking; model cụ thể sẽ được bổ sung ở Task 02.
