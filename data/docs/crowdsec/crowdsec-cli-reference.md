---
title: CrowdSec CLI (cscli) — Tài liệu tham khảo thực chiến
author: Thien
date: 2026-05-05
version: 1.0
tags: [crowdsec, cscli, cli, reference, opnsense, freebsd]
---

# CrowdSec CLI (cscli) — Tài liệu tham khảo thực chiến

> Tổng hợp các lệnh `cscli` đã dùng thực tế trong quá trình tích hợp CrowdSec + Suricata trên OPNsense/FreeBSD. Tổ chức theo nhóm chức năng để tra cứu nhanh.

---

## Mục lục

- [Version & Health](#version--health)
- [Metrics](#metrics)
- [Collections](#collections)
- [Parsers & Scenarios](#parsers--scenarios)
- [Alerts](#alerts)
- [Decisions](#decisions)
- [Bouncers](#bouncers)
- [Allowlists](#allowlists)
- [Explain (Debug)](#explain-debug)
- [Machines](#machines)
- [Service Management](#service-management)

---

## Version & Health

```sh
# Kiểm tra version CrowdSec
cscli version
```

**Output mẫu**:
```
version: v1.6.x
Codename: ...
Platform: freebsd
```

---

## Metrics

Lệnh quan trọng nhất để debug — xem trạng thái toàn bộ pipeline.

```sh
# Xem toàn bộ metrics
cscli metrics

# Lọc chỉ xem acquisition (tầng 1 — log có được đọc không)
cscli metrics | grep "eve.json"
cscli metrics | grep "Acquisition" -A 10

# Lọc xem parser metrics (tầng 2 — log có được parse không)
cscli metrics | grep "Parser" -A 20

# Lọc xem scenario metrics (tầng 3 — bucket có overflow không)
cscli metrics | grep "Scenario" -A 10

# Lọc xem bouncer metrics (tầng 5 — bouncer có nhận decisions không)
cscli metrics | grep "Bouncer" -A 10
```

### Đọc Acquisition Metrics

```
│ Source                          │ Lines read │ Lines parsed │ Lines unparsed │ Lines poured │
│ file:/var/log/suricata/eve.json │ 151.28k    │ -            │ 151.28k        │ -            │
```

| Cột | Ý nghĩa | Trạng thái tốt |
|-----|---------|----------------|
| Lines read | Số dòng CrowdSec đã đọc từ file | > 0 |
| Lines parsed | Số dòng được parser xử lý thành công | > 0 |
| Lines unparsed | Số dòng không có parser nào match | Thấp |
| Lines poured | Số dòng được đưa vào bucket scenario | > 0 |

> ⚠️ `Lines read > 0` nhưng `Lines parsed = -` → tầng 2 fail (parser không match)

---

## Collections

```sh
# Liệt kê tất cả collections đã cài
cscli collections list

# Lọc tìm collection cụ thể
cscli collections list | grep suricata

# Cài collection
cscli collections install crowdsecurity/suricata

# Gỡ collection
cscli collections remove crowdsecurity/suricata

# Gỡ và xóa file cấu hình (--purge)
cscli collections remove crowdsecurity/suricata --purge

# Upgrade collection lên version mới nhất
cscli collections upgrade crowdsecurity/suricata

# Xem chi tiết 1 collection
cscli collections inspect crowdsecurity/suricata
```

**Collections đang dùng trong hệ thống**:
```
crowdsecurity/suricata
crowdsecurity/whitelist-good-actors
firewallservices/opnsense  (hoặc tương đương)
```

---

## Parsers & Scenarios

```sh
# Liệt kê parsers đang active
cscli parsers list

# Lọc tìm parser suricata
cscli parsers list | grep suricata

# Liệt kê scenarios đang active
cscli scenarios list

# Xem chi tiết 1 parser
cscli parsers inspect crowdsecurity/suricata-logs

# Xem chi tiết 1 postoverflow
cscli postoverflows list
cscli postoverflows inspect crowdsecurity/cdn-whitelist
```

---

## Alerts

```sh
# Liệt kê alerts gần nhất (mặc định 10)
cscli alerts list

# Liệt kê nhiều hơn
cscli alerts list -l 50

# Lọc theo IP
cscli alerts list --ip 203.210.240.98

# Lọc theo scenario
cscli alerts list --scenario crowdsecurity/suricata-major-severity

# Lọc theo khoảng thời gian
cscli alerts list --since 1h
cscli alerts list --until 2h

# Xem chi tiết 1 alert theo ID
cscli alerts inspect 354

# Xóa tất cả alerts (dùng cẩn thận)
cscli alerts delete --all
```

**Output mẫu**:
```
+-----+--------------------+---------------------------------------+---------+------------------+-----------+
|  ID |        value       |                reason                 | country |        as        | decisions |
+-----+--------------------+---------------------------------------+---------+------------------+-----------+
| 354 | Ip:203.210.240.109 | openappsec/openappsec-probing         | VN      | 45899 VNPT Corp  | ban:1     |
| 353 | Ip:203.210.240.98  | crowdsecurity/suricata-major-severity | VN      | 45899 VNPT Corp  | ban:1     |
```

---

## Decisions

```sh
# Liệt kê decisions đang active
cscli decisions list

# Lọc theo IP cụ thể
cscli decisions list --ip 1.2.3.4

# Lọc theo loại action
cscli decisions list --type ban

# Thêm decision thủ công (ban IP)
cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual ban"

# Thêm decision ban cả subnet
cscli decisions add --range 1.2.3.0/24 --duration 24h --reason "subnet ban"

# Xóa decision theo ID
cscli decisions delete --id 1827027

# Xóa decision theo IP
cscli decisions delete --ip 1.2.3.4

# Xóa tất cả decisions local (không xóa từ CAPI)
cscli decisions delete --all

# Whitelist IP vĩnh viễn (duration 0 = không expire)
cscli decisions add --ip 192.168.0.73 --type whitelist --duration 0
```

**Output mẫu**:
```
╭─────────┬──────────┬───────────────────┬───────────────────────────────────────┬────────┬─────────╮
│    ID   │  Source  │    Scope:Value    │                 Reason                │ Action │ Country │
├─────────┼──────────┼───────────────────┼───────────────────────────────────────┼────────┼─────────┤
│ 1827028 │ crowdsec │ Ip:203.210.240.98 │ crowdsecurity/suricata-major-severity │ ban    │         │
│ 1827027 │ crowdsec │ Ip:1.2.3.4        │ crowdsecurity/suricata-major-severity │ ban    │         │
╰─────────┴──────────┴───────────────────┴───────────────────────────────────────┴────────┴─────────╯
```

---

## Bouncers

```sh
# Liệt kê bouncers đang kết nối LAPI
cscli bouncers list

# Thêm bouncer mới (sinh API key)
cscli bouncers add cs-firewall-bouncer-new

# Xóa bouncer (invalidate API key)
cscli bouncers delete cs-firewall-bouncer-1775801987

# Xem chi tiết bouncer
cscli bouncers inspect cs-firewall-bouncer-new
```

**Output mẫu**:
```
╭────────────────────────────────┬──────────┬─────────────────────┬──────────────╮
│              Name              │   IP     │      Last Pull      │    Status    │
├────────────────────────────────┼──────────┼─────────────────────┼──────────────┤
│ cs-firewall-bouncer-1775801987 │ 127.0.0.1│ 2026-05-05 16:27:23 │ VALID        │
│ mbx-firewall-bouncer           │ 127.0.0.1│ 2026-05-05 16:27:23 │ VALID        │
╰────────────────────────────────┴──────────┴─────────────────────┴──────────────╯
```

> ⚠️ Nếu `last_pull` > 60s → bouncer không healthy, kiểm tra API key trong config file bouncer

---

## Allowlists

> Tính năng từ CrowdSec v1.6.8+. Phương pháp whitelist IP/CIDR được khuyến nghị nhất.

```sh
# Tạo allowlist mới
cscli allowlists create internal-infra --description "Internal infrastructure IPs"

# Thêm IP vào allowlist
cscli allowlists add internal-infra 192.168.0.73
cscli allowlists add internal-infra 192.168.0.147

# Thêm cả subnet
cscli allowlists add internal-infra 192.168.0.0/24

# Liệt kê tất cả allowlists
cscli allowlists list

# Xem chi tiết 1 allowlist (xem các IP đã thêm)
cscli allowlists inspect internal-infra

# Xóa IP khỏi allowlist
cscli allowlists remove internal-infra 192.168.0.73

# Xóa toàn bộ allowlist
cscli allowlists delete internal-infra
```

---

## Explain (Debug)

Công cụ quan trọng nhất để debug parser pipeline. Chạy 1 dòng log qua toàn bộ pipeline và hiển thị kết quả từng stage.

```sh
# Test 1 file log qua pipeline
cscli explain --file /tmp/test_alert.log --type suricata -v

# Output ra file (vì tcsh không support 2>&1 pipe)
cscli explain --file /tmp/test_alert.log --type suricata -v > /tmp/explain_out.txt
cat /tmp/explain_out.txt

# Lọc kết quả quan trọng
grep -E "source_ip|log_type|proto|Scenario|success|failure|StrTime" /tmp/explain_out.txt
```

> ⚠️ **FreeBSD/tcsh**: `cscli explain --log -` (stdin) không hoạt động. Luôn dùng `--file`.

### Đọc output explain

```
line: {JSON log line}
  ├ s00-raw
  |   ├ 🔴 crowdsecurity/syslog-logs        ← không match
  |   └ 🟢 crowdsecurity/non-syslog (+5 ~8) ← match, set program=suricata
  ├ s01-parse
  |   └ 🟢 custom/suricata-evelogs (+13 ~2) ← match, extract fields
  |       └ create evt.Meta.source_ip : 192.168.0.73
  |       └ update evt.StrTime : -> 2026-05-04T15:43:48Z
  ├ s02-enrich
  |   └ 🟢 custom/suricata-xff-enrich       ← override IP từ XFF
  |       └ update evt.Meta.source_ip : 192.168.0.73 -> 203.210.240.98
  ├-------- parser success 🟢
  ├ Scenarios
  |   └ 🟢 crowdsecurity/suricata-major-severity  ← scenario trigger
```

| Symbol | Ý nghĩa |
|--------|---------|
| 🟢 | Parser/scenario match thành công |
| 🔴 | Không match, bỏ qua |
| `parser success 🟢` | Event đi qua toàn bộ parse pipeline thành công |
| `parser failure 🔴` | Không có parser nào match ở stage đó |

---

## Machines

```sh
# Liệt kê machines (Log Processors) đã đăng ký với LAPI
cscli machines list

# Xem metrics theo machine
cscli metrics | grep "Machines" -A 10
```

**Output mẫu**:
```
╭───────────┬───────────────┬────────┬───────╮
│  Machine  │     Route     │ Method │  Hits │
├───────────┼───────────────┼────────┼───────┤
│ mbx-agent │ /v1/alerts    │  GET   │     2 │
│ mbx-agent │ /v1/heartbeat │  GET   │ 17906 │
╰───────────┴───────────────┴────────┴───────╯
```

---

## Service Management

> Trên OPNsense/FreeBSD, dùng `service` thay vì `systemctl`.

```sh
# Khởi động lại CrowdSec (áp dụng config mới)
service crowdsec restart

# Reload config không restart (nhanh hơn, dùng sau khi sửa parser/scenario)
service crowdsec reload

# Kiểm tra trạng thái
service crowdsec status

# Khởi động/dừng
service crowdsec start
service crowdsec stop

# Restart bouncer sau khi đổi API key
service crowdsec-firewall-bouncer restart
```

---

## Workflow debug nhanh

Khi CrowdSec không block IP như mong đợi, chạy theo thứ tự:

```sh
# Bước 1: Tầng 1 — Log có được đọc không?
cscli metrics | grep "eve.json"
# Lines read > 0? Nếu không → kiểm tra acquis.d, file path, permission

# Bước 2: Tầng 2 — Log có được parse không?
# Lines parsed > 0? Nếu không → debug parser
grep '"event_type":"alert"' /var/log/suricata/eve.json | head -1 > /tmp/test.log
cscli explain --file /tmp/test.log --type suricata -v > /tmp/explain.txt
grep -E "🟢|🔴|failure|success" /tmp/explain.txt

# Bước 3: Tầng 3 — Scenario có trigger không?
cscli metrics | grep "Scenario" -A 10
# Overflow > 0? Nếu không → xem filter condition trong scenario file

# Bước 4: Tầng 4 — Alert/Decision có tạo ra không?
cscli alerts list | head -10
cscli decisions list | head -10

# Bước 5: Tầng 5 — Bouncer có enforce không?
cscli bouncers list
# last_pull < 60s? Status = VALID?
pfctl -t crowdsec -T show | head -20
# IP có trong pf table không?
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│ NHÓM          │ LỆNH THƯỜNG DÙNG                           │
├───────────────┼─────────────────────────────────────────────┤
│ Debug         │ cscli metrics                               │
│               │ cscli explain --file [f] --type [t] -v      │
├───────────────┼─────────────────────────────────────────────┤
│ Monitoring    │ cscli alerts list                           │
│               │ cscli decisions list                        │
│               │ cscli bouncers list                         │
├───────────────┼─────────────────────────────────────────────┤
│ Collections   │ cscli collections install [name]            │
│               │ cscli collections list                      │
│               │ cscli collections upgrade [name]            │
├───────────────┼─────────────────────────────────────────────┤
│ Manual ban    │ cscli decisions add --ip [ip] --duration [d] │
│ Manual unban  │ cscli decisions delete --ip [ip]            │
├───────────────┼─────────────────────────────────────────────┤
│ Whitelist IP  │ cscli allowlists create [name]              │
│               │ cscli allowlists add [name] [ip]            │
├───────────────┼─────────────────────────────────────────────┤
│ Service       │ service crowdsec reload                     │
│ (FreeBSD)     │ service crowdsec restart                    │
└───────────────┴─────────────────────────────────────────────┘
```

---

## Tham khảo

- CrowdSec CLI Docs: https://docs.crowdsec.net/docs/next/cscli/cscli
- Metrics Reference: https://docs.crowdsec.net/docs/next/observability/metrics
- Hub Collections: https://app.crowdsec.net/hub
