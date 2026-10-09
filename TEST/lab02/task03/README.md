# Task 03 — Cấu hình xử lý bài 2

Ngày kiểm thử: 09/10/2026.

## Mục đích và phạm vi

Tạo cấu hình bất biến cho Decoder, Preprocessor và Flow Tracker, đọc bằng
`tomllib` có sẵn trong Python 3.12 và validation trước khi các module sử dụng.

Task này chỉ đọc/kiểm tra cấu hình. Chưa có runtime decoder/preprocessor/tracker
thực thi policy, chưa có CLI `--config`, chưa có timer xóa flow. Các phần đó sẽ
được triển khai ở task tương ứng. T01–T14 có bằng chứng riêng sau này.

## File chính

- `ids/config.py`: config dataclasses, policy enums, `ConfigError`, `load_config()`.
- `config/default.toml`: file mặc định có chú thích ý nghĩa từng policy.
- `tests/lab02/test_config.py`: test bộ đọc và validation.

## Giá trị mặc định

Các con số dưới đây là lựa chọn của dự án, không phải giá trị cố định trong PDF.

| Section | Tham số | Mặc định |
|---|---|---|
| decoder | default_charset | utf-8 |
| decoder | invalid_bytes_policy | replace |
| decoder | max_input_bytes | 1048576 byte (1 MiB) |
| decoder | max_output_bytes | 1048576 byte (1 MiB) |
| decoder | limit_policy | skip |
| preprocessor | invalid_event_policy | skip |
| preprocessor | unsupported_event_policy | mark |
| tracker | tcp_idle_timeout | 180 giây |
| tracker | udp_idle_timeout | 30 giây |
| tracker | expiry_check_interval | 1 giây |
| tracker | max_active_flows | 10000 |
| tracker | capacity_policy | evict_oldest |

## Hợp đồng policy cho các task sau

- Byte lỗi: `replace` giữ text có ký tự thay thế nhưng vẫn đánh dấu partial/error;
  `strict` báo decode error. Cả hai không làm dừng xử lý event tiếp theo.
- Decode vượt giới hạn: `skip` hoặc `error`, không decode dữ liệu vượt ngưỡng;
  giữ raw data và ghi status/reason.
- Event policy: `mark` ghi status/reason và tiếp tục với field an toàn; `skip`
  ghi status/reason rồi bỏ qua tracking. Cả hai vẫn cho phép ghi log event.
- Event invalid vẫn không được tracking nếu thiếu/sai endpoint hoặc thời gian
  bắt buộc, kể cả khi policy là `mark`. UNKNOWN application protocol không tự
  động làm invalid một event TCP/UDP có endpoint hợp lệ.
- Flow capacity: `evict_oldest` xuất/xóa flow có last_seen cũ nhất để nhận flow
  mới, ghi reason do giới hạn; `skip_new` giữ flow hiện có, ghi reason và bỏ qua
  flow mới. Eviction vì capacity khác với idle timeout.
- Timeout PCAP dựa trên event timestamp; live capture cần periodic expiry ngay
  cả khi không có packet mới. `expiry_check_interval` cấu hình chu kỳ đó.

## Đọc cấu hình

```python
from ids.config import load_config

defaults = load_config()  # Mặc định trong code, không phụ thuộc thư mục chạy.
config = load_config("config/default.toml")
print(config.tracker.tcp_idle_timeout)
```

`load_config(path)` hỗ trợ file chỉ ghi đè một phần:

```toml
[tracker]
tcp_idle_timeout = 60
```

Các tham số không ghi trong file giữ mặc định. File rỗng cũng dùng mặc định.
Nếu chỉ định một path không tồn tại hoặc sai định dạng, không âm thầm fallback.
Tên section/setting không nhận diện bị từ chối để tránh lỗi đánh máy bị bỏ qua.

## Validation

- Giới hạn byte và số flow: số nguyên dương, không nhận boolean hay số thập phân.
- Timeout và chu kỳ kiểm tra: số dương hữu hạn; không nhận 0, số âm, boolean,
  chuỗi số, NaN, infinity hoặc giá trị quá lớn không đổi được thành float hữu hạn.
- Charset tối thiểu: ASCII/UTF-8; alias hợp lệ được đưa về tên thống nhất.
- Policy phải thuộc các enum đã định nghĩa, phân biệt chữ hoa/chữ thường.
- Section phải là TOML table; key lạ bị từ chối.
- File không đọc được, TOML hỏng, byte UTF-8 lỗi được báo bằng `ConfigError`.
- Khởi tạo config dataclass trực tiếp cũng thực hiện validation; không thể sửa
  các field sau khi đã tạo config.

## Lệnh kiểm thử

```bash
./venv/bin/python -m pytest tests/lab02/test_config.py -v
./venv/bin/python -m pytest -q
```

## Kết quả mong đợi và thực tế

- Mặc định trong TOML khớp mặc định trong code: PASS.
- Ghi đè một phần giữ nguyên các giá trị còn lại: PASS.
- Từ chối file/settings/policies/limits sai với message rõ ràng: PASS.
- Config đã tải bất biến; ghi đè không ảnh hưởng lần load khác: PASS.
- Các test model và bài 1 tiếp tục hoạt động: PASS.
- Test cấu hình: 42 passed.
- Toàn bộ suite: 117 passed (75 test trước đó và 42 test cấu hình).
- Log stdout/stderr thực tế được lưu tại `result.txt`.

Kết thúc Task 03: hoàn thành nền tảng model + cấu hình của giai đoạn 1.
