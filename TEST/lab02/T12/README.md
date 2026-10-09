# T12 — Idle timeout TCP/UDP

PCAP tổng hợp 4 packet, explicit MAC, timestamps UTC Decimal; không cần root.
Config tcp_idle_timeout=3s, udp_idle_timeout=2s, interval0.1s. TCP/UDP cùng
endpoint pair 10.0.0.2:51000 ↔ 10.0.0.1:8080 vẫn là hai flow riêng.

| Bước | Packet hoặc maintenance | Expected active | Actual active |
|---|---|---:|---:|
| 1–3 | TCP ACK t0 (54B), UDP t0 (42B), TCP ACK t1 (54B) | 2 | 2 |
| 4 | expire(t2), không nhận packet mới; UDP idle2s | 1 | 1 |
| 5 | expire(t4), TCP last_seen=t1, idle3s | 0 | 0 |
| 6 | UDP t4.1, cùng tuple, generation2 (42B) | 1 | 1 |
| 7 | expire(t6.1), UDP generation2 idle2s | 0 | 0 |

Expected literals exact-match checkpoints.json và flows.jsonl. Ba summaries:
UDP gen1 1/42B/duration0, TCP 2/108B/duration1, UDP gen2 1/42B/duration0.
Total4 packet/192B, end_reason=idle_timeout. TCP observed_state=NEW, state=CLOSED
vì lifetime timeout; ACKcount2, FIN/RST0, không bịa wire FIN. UDP state=null.
end_time t2/t4/t6.1 riêng, không cộng idle wait vào duration. TCP contexts và
active table đều rỗng cuối case. Events cũ vẫn giữ association snapshot NEW/null.

input.pcap/config.toml/expected.json/actual.jsonl/flows.jsonl/checkpoints.json
lưu đầy đủ input, associations, cleanup stages và statistics. result.txt là
stdout/exit code script, integration1 passed, full suite805 passed.

```bash
./venv/bin/python -m tests.lab02.reproduce_t12
./venv/bin/python -m pytest tests/lab02/test_t12_idle_timeout.py -v
```

Tái hiện ngoài repo: --output-dir /tmp/ids-t12. Explicit expiry không sleep,
không cần packet để trigger. 32 tests timeout/capacity/backpressure/atomicity
và regression trước ở TEST/lab02/task16/. Chưa CLI/live timer (Task17).
