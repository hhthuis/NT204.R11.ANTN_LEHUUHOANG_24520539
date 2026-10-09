# Task 16 — Idle timeout và capacity

TrackerConfig được dùng bởi FlowTracker; timeout TCP/UDP riêng, >= là ngưỡng
hết hạn. Clock UTC=max timestamps đã chấp nhận hoặc maintenance time; skip/
invalid không đổi clock, timestamp lệch thứ tự không làm clock lùi. Packet quá
cũ không tạo lại flow đã hết hạn (tracker_late_event). Same key luôn kiểm tra
expiry dù chưa tới sweep interval; bảng đầy quét expired trước policy capacity.

expire(now) chạy khi không có packet và trả số flow đã loại trong một batch.
Caller write/ack summaries giữa các batch rồi gọi lại cho tới trả0. expiry/
capacity TCP chưa terminal dùng CLOSED, observed_state giữ state packet cuối;
không bịa FIN/RST counters. RESET/CLOSED giữ nguyên. last_seen/duration không
cộng thời gian chờ timeout; end_time riêng ghi thời điểm xuất/maintenance.

Capacity evict_oldest chọn (last_seen,flow_id), export snapshot rồi xóa record/
TCP contexts. skip_new ghi tracker_flow_capacity và giữ bảng; updates flow
hiện có vẫn được nhận. Pending queue bị giới hạn max_pending_summaries=10000;
full queue tạo backpressure, không âm thầm bỏ summaries. Tracker lập kế hoạch
expiry/eviction/reuse và tính statistics/state trước commit, lỗi không cập nhật dở.

pending_summary() peek detached, acknowledge_summary(id) FIFO chỉ gọi sau write
thành công. drain_completed_flows()/export_flows() giữ legacy inspection schema;
stream output dùng peek/ack để giữ end_reason/end_time/observed_state/schema_version.
finish(reason,now) batch bounded cho capture_eof/capture_stopped/capture_error,
state vẫn theo capture, không invent close. remove_flow là explicit ownership
transfer, generation per-key vẫn giữ để ID lifetime không trùng; generation
history chưa bounded (max_active_flows chỉ giới hạn resident records/context).

Files: ids/flows/expiry.py, ids/flows/tracker.py, ids/config.py,
config/default.toml; tests/lab02/test_flow_expiry.py (32 tests), flow_pcap_support
truyền config.tracker. Tests boundary, renewal, TCP/UDP/terminal cleanup,
interval, no-packet timer, late timestamp, capacity/ties, queue/full/recovery,
FIFO, finish batches, invalid config/time và atomicity. Source full suite804
passed; T07–T11/T13 regression PASS. stdout/commands trong result.txt.

T12 evidence có commit riêng. Live timer/output/EOF wiring thuộc Task17.
