---
title: CrowdSec + Suricata Integration trên OPNsense/FreeBSD
author: Thien
date: 2026-05-05
version: 1.0
tags: [crowdsec, suricata, opnsense, freebsd, ids, ips, security]
---

# CrowdSec + Suricata Integration trên OPNsense/FreeBSD

> **Mục đích**: Tài liệu ghi lại toàn bộ quá trình troubleshoot, các lỗi gặp phải, cách fix, và bài học kinh nghiệm khi tích hợp Suricata EVE JSON với CrowdSec trên OPNsense (FreeBSD). Dùng làm tài liệu tham khảo cho các lần triển khai tiếp theo.

---

## Môi trường

| Thành phần | Chi tiết |
|-----------|---------|
| OS | OPNsense trên FreeBSD |
| CrowdSec | Security Engine + LAPI |
| Suricata | IDS mode, monitor interface `vtnet0` (LAN) |
| Topology | Internet → OPNsense → HAProxy (`192.168.0.73`) → Zimbra (`192.168.0.147`) |
| Bouncer | `cs-firewall-bouncer` (pf) + `mbx-firewall-bouncer` |
| Shell | tcsh (FreeBSD default — ảnh hưởng đến cú pháp command) |

### Sơ đồ luồng mục tiêu

```
Traffic
  │
  ▼
Suricata (IDS, vtnet0 LAN)
  │  eve.json
  ▼
CrowdSec Log Processor
  │  s00-raw → s01-parse → s02-enrich → Scenario
  ▼
LAPI Decision (ban)
  │
  ▼
pf Bouncer → block IP trên firewall
```

---

## Timeline & Vấn đề đã xử lý

---

### Vấn đề 1 — Suricata EVE JSON: 0 parsed (tầng 2 fail)

**Triệu chứng** (`cscli metrics`):

```
│ file:/var/log/suricata/eve.json │ 151.28k │ - │ 151.28k │ - │
```

151k dòng được đọc (Lines read) nhưng **0 parsed, 0 poured**.

**Chẩn đoán ban đầu (sai)**: Nghi collection chưa cài, acquis.d sai format.

**Xác nhận thực tế**:

```sh
cscli collections list | grep suricata
# → crowdsecurity/suricata  ✔️  enabled   (đã cài)

cat /usr/local/etc/crowdsec/acquis.d/suricata.yaml
# → filenames: /var/log/suricata/eve.json
# → labels: type: suricata    (đúng format)
```

Cả hai đều đúng → root cause phải nằm ở parser file.

**Điều tra parser**:

```sh
ls /usr/local/etc/crowdsec/parsers/s01-parse/
# → suricata-logs.yaml  (không phải suricata-evelogs.yaml như Linux)

grep "^name:" /usr/local/etc/crowdsec/parsers/s01-parse/suricata-logs.yaml
# → name: crowdsecurity/suricata-fastlogs
# → name: crowdsecurity/suricata-evelogs
```

File `suricata-logs.yaml` chứa **2 parser documents** trong 1 file (YAML multi-document, phân cách bằng `---`).

**Root cause thực sự** — Filter của `suricata-evelogs` sai trên FreeBSD:

```yaml
# File gốc (BUG trên FreeBSD)
filter: |
  evt.Parsed.program == "suricata-evelogs" && ...
#                         ↑ string này không tồn tại trên FreeBSD

# non-syslog parser trên FreeBSD set:
# evt.Parsed.program = "suricata"   (Linux set = "suricata-evelogs")
```

**Xác nhận qua `cscli explain`**:

```sh
grep '"event_type":"alert"' /var/log/suricata/eve.json | head -1 > /tmp/test_alert.log
cscli explain --file /tmp/test_alert.log --type suricata -v > /tmp/explain_out.txt
# → s01-parse: 🔴 crowdsecurity/suricata-evelogs  (NO MATCH)
# → parser failure 🔴
```

**Fix**: Tạo custom parser file với filter đã sửa.

> ⚠️ **Lý do không sửa file gốc**: File gốc sẽ bị overwrite khi `cscli collections upgrade`. Custom file tách biệt là cách chuẩn (update-safe).

> ⚠️ **Tên file phải đứng trước `suricata-logs.yaml` alphabetically** vì CrowdSec xử lý theo thứ tự alphabetical và dừng khi parser match (`onsuccess: next_stage`).

```sh
cat > /usr/local/etc/crowdsec/parsers/s01-parse/suricata-evelogs.yaml << 'EOF'
onsuccess: next_stage
filter: |
  evt.Parsed.program == "suricata" && JsonExtract(evt.Parsed.message, "event_type") == "alert"
name: custom/suricata-evelogs
description: "Fix suricata-evelogs parser for OPNsense FreeBSD (program=suricata)"
nodes:
  - grok:
      pattern: '%{TIMESTAMP_ISO8601:time}(\-|\+)%{INT}'
      expression: JsonExtract(evt.Parsed.message, "timestamp")
statics:
  - meta: service
    value: suricata
  - meta: log_type
    value: suricata_alert
  - meta: sub_log_type
    value: suricata_alert_eve_json
  - target: evt.StrTime
    expression: evt.Parsed.time + 'Z'
  - target: evt.Meta.suricata_flow_id
    expression: JsonExtract(evt.Parsed.message, "flow_id")
  - target: evt.Meta.source_ip
    expression: JsonExtract(evt.Parsed.message, "src_ip")
  - target: evt.Parsed.dest_ip
    expression: JsonExtract(evt.Parsed.message, "dest_ip")
  - target: evt.Parsed.dest_port
    expression: JsonExtract(evt.Parsed.message, "dest_port")
  - target: evt.Parsed.proto
    expression: JsonExtract(evt.Parsed.message, "proto")
  - target: evt.Meta.suricata_alert_signature_id
    expression: JsonExtract(evt.Parsed.message, "alert.signature_id")
  - target: evt.Parsed.suricata_alert_signature_rev
    expression: JsonExtract(evt.Parsed.message, "alert.rev")
  - target: evt.Parsed.suricata_alert_signature
    expression: JsonExtract(evt.Parsed.message, "alert.signature")
  - target: evt.Meta.suricata_rule_severity
    expression: JsonExtract(evt.Parsed.message, "alert.severity")
EOF
service crowdsec reload
```

**Kết quả sau fix**:

```
s01-parse: 🟢 custom/suricata-evelogs  (+13 ~2)
  └ create evt.Meta.source_ip : 192.168.0.73
  └ update evt.StrTime : -> 2026-05-04T15:43:48.115086Z
```

---

### Vấn đề 2 — source_ip là HAProxy thay vì IP attacker thật

**Triệu chứng**:

```
evt.Meta.source_ip : 192.168.0.73   ← HAProxy, không phải attacker
```

**Root cause**: Topology có HAProxy đứng giữa. Suricata thấy traffic HAProxy → OPNsense nên `src_ip` trong EVE JSON là `192.168.0.73`. IP thật của attacker nằm trong XFF header:

```json
"http": {
  "xff": "203.210.240.98",   ← IP attacker thật
  ...
}
"src_ip": "192.168.0.73"     ← HAProxy
```

**Nếu không fix**: CrowdSec sẽ ban `192.168.0.73` (HAProxy) thay vì IP attacker → toàn bộ traffic qua HAProxy bị block.

**Fix**: Tạo XFF enrich parser ở stage s02-enrich để override `source_ip`:

```sh
cat > /usr/local/etc/crowdsec/parsers/s02-enrich/suricata-xff-enrich.yaml << 'EOF'
onsuccess: next_stage
filter: |
  evt.Meta.log_type == "suricata_alert" &&
  JsonExtract(evt.Parsed.message, "http.xff") != ""
name: custom/suricata-xff-enrich
description: "Override source_ip with XFF real IP for Suricata behind HAProxy"
statics:
  - meta: source_ip
    expression: JsonExtract(evt.Parsed.message, "http.xff")
EOF
service crowdsec reload
```

**Kết quả sau fix**:

```
create evt.Meta.source_ip : 192.168.0.73           ← s01 set ban đầu
update evt.Meta.source_ip : 192.168.0.73 -> 203.210.240.98  ← s02 override ✔️
```

---

### Vấn đề 3 — API Key lộ trong EVE JSON log

**Phát hiện tình cờ** khi đọc `head -3 /var/log/suricata/eve.json`:

```json
{
  "http": {
    "url": "/v1/decisions/stream",
    "request_headers": [
      {"name": "X-Api-Key", "value": "vcKX3jKCyeXrYK1K..."}
    ]
  }
}
```

Suricata đang log **toàn bộ HTTP request headers** bao gồm CrowdSec bouncer API key.

**Nguyên nhân**: Suricata monitor LAN interface `vtnet0` → thấy traffic bouncer poll LAPI (port 8080) → log đầy đủ headers.

**Rủi ro**: File `eve.json` có thể được đọc bởi nhiều process. API key này cho phép query/manipulate LAPI decisions.

**Fix**:
1. Tắt HTTP request header logging trong Suricata (OPNsense UI: Services → Intrusion Detection → EVE Log settings)
2. Rotate API key bị lộ:

```sh
cscli bouncers delete cs-firewall-bouncer-1775801987
cscli bouncers add cs-firewall-bouncer-new
# Cập nhật key mới vào /usr/local/etc/crowdsec-firewall-bouncer/crowdsec-firewall-bouncer.yaml
service crowdsec-firewall-bouncer restart
```

---

### Vấn đề 4 — tcsh shell: syntax khác bash

Nhiều lệnh chuẩn trên Linux/bash **không hoạt động trên tcsh** (FreeBSD default shell của OPNsense).

| Lệnh | Bash (Linux) | tcsh (FreeBSD) |
|------|-------------|----------------|
| Redirect stderr | `cmd 2>&1` | `cmd >& file` hoặc tạo file output |
| Heredoc | `cat << 'EOF'` | **Không support** — dùng `echo` hoặc Python |
| Pipe stderr | `cmd 2>&1 \| grep` | `(cmd > /tmp/out.txt) >& /dev/null; grep ... /tmp/out.txt` |

**Workaround đã dùng**:

```sh
# Thay vì: cmd 2>&1 | grep "pattern"
cmd > /tmp/output.txt
grep "pattern" /tmp/output.txt

# Thay vì: cat << 'EOF' >> file
echo 'single line JSON' >> file

# Hoặc dùng Python để tạo JSON sạch:
python3 -c "import json; print(json.dumps({...}))" >> /var/log/suricata/eve.json
```

---

### Vấn đề 5 — cscli explain không nhận stdin trên FreeBSD

**Triệu chứng**:

```sh
grep '"event_type":"alert"' /var/log/suricata/eve.json | head -1 | cscli explain --log - --type suricata -v
# Error: cscli explain: the log file is empty: /tmp/cscli_explain.../cscli_test_tmp.log
```

`--log -` (stdin) không hoạt động trên FreeBSD.

**Workaround**:

```sh
grep '"event_type":"alert"' /var/log/suricata/eve.json | head -1 > /tmp/test_alert.log
cscli explain --file /tmp/test_alert.log --type suricata -v > /tmp/explain_out.txt
cat /tmp/explain_out.txt
```

---

### Vấn đề 6 — eve.json chỉ có HTTP/anomaly events, không có alert

**Phát hiện**:

```sh
grep -o '"event_type":"[^"]*"' /var/log/suricata/eve.json | sort | uniq -c | sort -rn
# 112479 "event_type":"http"
#   2879 "event_type":"anomaly"
#     52 "event_type":"alert"
```

**Nguyên nhân**: Suricata monitor LAN interface → 99.9% traffic là HTTP nội bộ (đặc biệt là bouncer poll LAPI `/v1/decisions/stream` mỗi 10s). Chỉ có 52 alerts thật.

**Hàm ý**: Parser `crowdsecurity/suricata-evelogs` chỉ match `event_type == "alert"` → 99.9% lines sẽ parse được bởi `non-syslog` (fallback) nhưng không pour vào bucket — **đây là behavior đúng**, không phải bug.

---

### Vấn đề 7 — YAML multi-document: nhầm lẫn khi copy

**File gốc `suricata-logs.yaml`** chứa 2 parser trong 1 file:

```yaml
# Document 1
name: crowdsecurity/suricata-fastlogs
filter: "evt.Parsed.program == 'suricata-fastlogs'"
# ... parse fast.log (text format)
---
# Document 2
name: crowdsecurity/suricata-evelogs
filter: evt.Parsed.program == "suricata-evelogs"
# ... parse eve.json (JSON format) ← BUG ở đây
```

**Lỗi thực tế**: Khi tạo fix file, đã copy nhầm cả 2 documents vào file mới → file fix chứa y hệt file gốc → không có tác dụng.

**Bài học**: Custom fix file chỉ nên chứa **đúng 1 document** — document cần fix. Document kia giữ nguyên trong file gốc.

**Verify đúng**:

```sh
grep -c "^name:" /usr/local/etc/crowdsec/parsers/s01-parse/suricata-evelogs.yaml
# Phải ra: 1  (chỉ 1 parser)
```

---

### Vấn đề 8 — Whitelist folder không tồn tại

**Triệu chứng**:

```sh
ls /usr/local/etc/crowdsec/whitelists
# ls: /usr/local/etc/crowdsec/whitelists: No such file or directory
```

Trên OPNsense/FreeBSD, whitelist **không có folder riêng** mà nằm ở:

- **Parser whitelist**: `/usr/local/etc/crowdsec/parsers/s02-enrich/`
- **Postoverflow whitelist**: `/usr/local/etc/crowdsec/postoverflows/s01-whitelist/`

---

## Kết quả cuối cùng

Sau khi fix tất cả các vấn đề trên, pipeline hoàn chỉnh:

```
cscli decisions list:
│ 1827028 │ crowdsec │ Ip:203.210.240.98 │ crowdsecurity/suricata-major-severity │ ban │
│ 1827027 │ crowdsec │ Ip:1.2.3.4        │ crowdsecurity/suricata-major-severity │ ban │
```

---

## Tổng hợp các file đã tạo

| File | Mục đích |
|------|---------|
| `/usr/local/etc/crowdsec/acquis.d/suricata.yaml` | Acquisition: đọc eve.json với `type: suricata` |
| `/usr/local/etc/crowdsec/parsers/s01-parse/suricata-evelogs.yaml` | Fix parser: `program == "suricata"` thay vì `"suricata-evelogs"` |
| `/usr/local/etc/crowdsec/parsers/s02-enrich/suricata-xff-enrich.yaml` | XFF enrich: override `source_ip` từ `http.xff` |
| `/usr/local/etc/crowdsec/postoverflows/s01-whitelist/internal-whitelist.yaml` | Whitelist HAProxy/OPNsense khỏi bị ban |

### Nội dung các file

#### `/usr/local/etc/crowdsec/acquis.d/suricata.yaml`

```yaml
filenames:
  - /var/log/suricata/eve.json
labels:
  type: suricata
```

#### `/usr/local/etc/crowdsec/parsers/s01-parse/suricata-evelogs.yaml`

```yaml
onsuccess: next_stage
filter: |
  evt.Parsed.program == "suricata" && JsonExtract(evt.Parsed.message, "event_type") == "alert"
name: custom/suricata-evelogs
description: "Fix suricata-evelogs parser for OPNsense FreeBSD"
nodes:
  - grok:
      pattern: '%{TIMESTAMP_ISO8601:time}(\-|\+)%{INT}'
      expression: JsonExtract(evt.Parsed.message, "timestamp")
statics:
  - meta: service
    value: suricata
  - meta: log_type
    value: suricata_alert
  - meta: sub_log_type
    value: suricata_alert_eve_json
  - target: evt.StrTime
    expression: evt.Parsed.time + 'Z'
  - target: evt.Meta.suricata_flow_id
    expression: JsonExtract(evt.Parsed.message, "flow_id")
  - target: evt.Meta.source_ip
    expression: JsonExtract(evt.Parsed.message, "src_ip")
  - target: evt.Parsed.dest_ip
    expression: JsonExtract(evt.Parsed.message, "dest_ip")
  - target: evt.Parsed.dest_port
    expression: JsonExtract(evt.Parsed.message, "dest_port")
  - target: evt.Parsed.proto
    expression: JsonExtract(evt.Parsed.message, "proto")
  - target: evt.Meta.suricata_alert_signature_id
    expression: JsonExtract(evt.Parsed.message, "alert.signature_id")
  - target: evt.Parsed.suricata_alert_signature_rev
    expression: JsonExtract(evt.Parsed.message, "alert.rev")
  - target: evt.Parsed.suricata_alert_signature
    expression: JsonExtract(evt.Parsed.message, "alert.signature")
  - target: evt.Meta.suricata_rule_severity
    expression: JsonExtract(evt.Parsed.message, "alert.severity")
```

#### `/usr/local/etc/crowdsec/parsers/s02-enrich/suricata-xff-enrich.yaml`

```yaml
onsuccess: next_stage
filter: |
  evt.Meta.log_type == "suricata_alert" &&
  JsonExtract(evt.Parsed.message, "http.xff") != ""
name: custom/suricata-xff-enrich
description: "Override source_ip with XFF real IP for Suricata behind HAProxy"
statics:
  - meta: source_ip
    expression: JsonExtract(evt.Parsed.message, "http.xff")
```

#### `/usr/local/etc/crowdsec/postoverflows/s01-whitelist/internal-whitelist.yaml`

```yaml
name: custom/internal-whitelist
description: "Never ban internal infrastructure IPs"
whitelist:
  reason: "HAProxy and OPNsense internal IPs"
  expression:
    - evt.Overflow.Alert.Source.IP == "192.168.0.73"
    - evt.Overflow.Alert.Source.IP == "192.168.0.147"
```

---

## Bài học kinh nghiệm

### 1. FreeBSD vs Linux packaging khác nhau

CrowdSec package trên OPNsense/FreeBSD có một số khác biệt so với Linux:

- `non-syslog` parser set `evt.Parsed.program = "suricata"` thay vì `"suricata-evelogs"`
- Parser files nằm ở `/usr/local/etc/crowdsec/` thay vì `/etc/crowdsec/`
- Shell mặc định là **tcsh**, không phải bash → nhiều command chuẩn không hoạt động
- `cscli explain --log -` (stdin) không hoạt động trên FreeBSD

### 2. Không bao giờ sửa file hub gốc

File trong `/usr/local/etc/crowdsec/parsers/`, `/usr/local/etc/crowdsec/scenarios/` do `cscli collections install` tạo ra sẽ **bị overwrite** khi upgrade. Luôn tạo file custom riêng.

### 3. Thứ tự alphabetical quan trọng

CrowdSec xử lý parser files theo thứ tự alphabetical. Với `onsuccess: next_stage`, parser match đầu tiên sẽ "thắng" và các parser sau không được chạy. Khi tạo override file, đặt tên sao cho đứng **trước** file gốc.

```
suricata-evelogs.yaml   ← 'e' < 'l' → chạy TRƯỚC  ✔️
suricata-logs.yaml      ← chạy SAU, không đến lượt
```

### 4. Debug theo 5 tầng pipeline

Khi CrowdSec không hoạt động, luôn debug theo thứ tự tầng:

```
Tầng 1 (Acquisition): cscli metrics → "Lines read" > 0?
Tầng 2 (Parse):       cscli metrics → "Lines parsed" > 0?
                       cscli explain --file ... -v → 🟢 hay 🔴?
Tầng 3 (Scenario):    cscli metrics → "Bucket overflow" > 0?
Tầng 4 (LAPI):        cscli alerts list → có alerts?
                       cscli decisions list → có decisions?
Tầng 5 (Bouncer):     cscli bouncers list → last_pull < 60s?
                       pfctl -t crowdsec -T show → có IP?
```

**Không nhảy thẳng vào log** trước khi xem metrics. Không đoán nguyên nhân trước khi xác định tầng fail.

### 5. XFF là bắt buộc khi có reverse proxy

Bất kỳ khi nào CrowdSec đứng sau reverse proxy (HAProxy, Nginx, Traefik), phải xử lý XFF header để lấy IP thật của attacker. Nếu không, CrowdSec sẽ ban **proxy server** thay vì attacker → toàn bộ traffic bị block.

Field XFF trong Suricata EVE JSON: `http.xff` (truy cập qua `JsonExtract(evt.Parsed.message, "http.xff")`).

### 6. Parser whitelist vs Postoverflow whitelist — field khác nhau

| Loại | Field IP | Khi nào dùng |
|------|----------|-------------|
| Parser whitelist (`s02-enrich`) | `evt.Meta.source_ip` | Discard event trước bucket, tiết kiệm CPU |
| Postoverflow whitelist (`s01-whitelist`) | `evt.Overflow.Alert.Source.IP` | Sau overflow, trước decision |
| AllowList (`cscli allowlists`) | IP/CIDR trực tiếp | Đơn giản nhất, v1.6.8+ |

> ⚠️ Nhầm field là lý do phổ biến nhất khiến whitelist không hoạt động.

### 7. Inject test event để verify live pipeline

`cscli explain` chỉ test offline. Để verify toàn bộ pipeline live (bao gồm bouncer enforce):

```sh
# Inject alert test vào eve.json
python3 -c "import json; print(json.dumps({
  'timestamp': '2026-05-05T17:00:00.000000+0700',
  'event_type': 'alert',
  'src_ip': '192.168.0.73',
  'proto': 'TCP',
  'alert': {'severity': 1, 'signature': 'Test'},
  'http': {'xff': '1.2.3.4'},
  'app_proto': 'http'
}))" >> /var/log/suricata/eve.json

sleep 15
cscli decisions list | grep "1.2.3.4"
# Nếu thấy → pipeline end-to-end OK ✔️
```

---

## Checklist triển khai lại

```
[ ] cài os-crowdsec + os-crowdsec-firewall-bouncer từ OPNsense Plugins
[ ] cscli collections install crowdsecurity/suricata
[ ] Tạo /usr/local/etc/crowdsec/acquis.d/suricata.yaml (type: suricata)
[ ] Verify Suricata EVE JSON đang ghi file (ls -la /var/log/suricata/eve.json)
[ ] Tạo /parsers/s01-parse/suricata-evelogs.yaml (fix program == "suricata")
[ ] Tạo /parsers/s02-enrich/suricata-xff-enrich.yaml (nếu có HAProxy/reverse proxy)
[ ] Tạo /postoverflows/s01-whitelist/internal-whitelist.yaml
[ ] service crowdsec reload
[ ] cscli metrics → Lines read > 0               (tầng 1 OK)
[ ] cscli explain --file [alert.log] --type suricata -v → 🟢  (tầng 2 OK)
[ ] Inject test alert → cscli decisions list → IP thật bị ban (end-to-end OK)
[ ] Tắt HTTP request header logging trong Suricata (tránh lộ API key)
[ ] Rotate bouncer API key nếu đã bị log vào eve.json
```

---

## Tham khảo

- CrowdSec Docs: https://docs.crowdsec.net/
- OPNsense Plugin: https://docs.crowdsec.net/u/getting_started/installation/opnsense
- Suricata Collection: https://app.crowdsec.net/hub/collections/crowdsecurity/suricata
- Whitelist Guide: https://docs.crowdsec.net/u/getting_started/post_installation/whitelists/
- Parser Format: https://docs.crowdsec.net/docs/next/log_processor/parsers/intro/
- pf Bouncer: https://docs.crowdsec.net/u/bouncers/firewall
