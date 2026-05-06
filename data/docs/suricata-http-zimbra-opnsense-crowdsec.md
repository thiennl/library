---
title: Triển khai Suricata HTTP/Zimbra trên OPNsense 26.1 với CrowdSec
author: Infra Team
date: 2026-04-28
version: 1.2
tags: [suricata, opnsense, crowdsec, zimbra, ids, http-security]
---

# Triển khai Suricata HTTP/Zimbra trên OPNsense 26.1 + CrowdSec

## Tổng quan

Tài liệu này hướng dẫn triển khai **Suricata ở chế độ IDS (PCAP mode)** trên OPNsense 26.1 để giám sát **HTTP traffic trên LAN interface** — nằm sau HAProxy, giám sát traffic đã được TLS termination — đặc biệt là HTTP vào Zimbra mail server — kết hợp với **CrowdSec** để tự động block attacker dựa trên Suricata alert.

### Lý do dùng IDS (PCAP) thay vì IPS (Divert)

OPNsense 26.1 chạy trên **OpenStack/KVM với virtio NIC** gặp bug đã biết [#10097](https://github.com/opnsense/core/issues/10097): Divert IPS mode không generate `ipfw` rules → không block được traffic. Workaround hiện tại là dùng **PCAP mode (IDS) + CrowdSec bouncer** để có tác dụng tương đương IPS với độ trễ 1–3 giây.

### Kiến trúc tổng thể

```
Internet (attacker: 203.0.113.1)
    ↓ HTTPS port 443
OPNsense WAN
    ↓
HAProxy (TLS termination)
    │  → thêm header: X-Forwarded-For: 203.0.113.1
    │  → thêm header: X-Real-IP: 203.0.113.1
    ↓ HTTP port 80 (plain text)
[LAN interface] ◄── Suricata sniff tại đây
    │  Thấy: src_ip = HAProxy LAN IP (vd: 10.0.0.1)
    │  Thấy: X-Forwarded-For: 203.0.113.1  ← IP thật attacker
    │  Thấy: full HTTP URI, method, headers, body
    ↓
Zimbra Nginx (port 80)
    ↓
mailboxd (port 8080)

CrowdSec Agent
    ↓ đọc eve.json realtime (~1-3s)
    ↓ parse X-Forwarded-For → lấy IP thật attacker
    ↓ scenario engine phán quyết
CrowdSec LAPI
    ↓
CrowdSec Bouncer (pf) → BAN 203.0.113.1 tại WAN firewall
    ↓ share lên CAPI
Community Blocklist (toàn cầu)
```

> ⚠️ **Điểm quan trọng**: Suricata thấy `src_ip` là IP của HAProxy (LAN), không phải IP attacker. IP thật của attacker nằm trong header `X-Forwarded-For`. Rules và CrowdSec phải xử lý điều này — xem chi tiết tại Phần 2 và Phần 3.

### Prerequisites

| Thành phần | Yêu cầu |
|---|---|
| OPNsense | 26.1.x (amd64) trên OpenStack/KVM |
| HAProxy | Đã cấu hình TLS termination, bật `X-Forwarded-For` |
| Suricata | Sniff trên **LAN interface** (interface giữa OPNsense và Zimbra VM) |
| CrowdSec | Đã cài và tích hợp vào OPNsense (bouncer pf active trên WAN) |
| Zimbra | Nhận HTTP port 80 từ HAProxy |
| RAM OPNsense | Tối thiểu 4GB (Suricata + CrowdSec) |

---

## Phần 1 — Cấu hình Suricata IDS trên OPNsense 26.1

### 1.1 Tắt Hardware Offloading (bắt buộc)

Offloading làm Suricata thấy packet bị modify ở NIC hardware → checksum sai → miss packet.

`Interfaces → Settings`

```
[ ] Hardware CRC          ← BỎ TICK
[ ] Hardware TSO          ← BỎ TICK
[ ] Hardware LRO          ← BỎ TICK
[ ] VLAN Hardware Filter  ← BỎ TICK
```

> **Apply → Reboot** nếu đây là lần đầu thay đổi setting này.

### 1.2 Cấu hình Suricata Administration

`Services → Intrusion Detection → Administration`

```
[✓] Enabled
[ ] IPS Mode              ← ĐỂ TRỐNG (dùng IDS/PCAP thay vì Divert IPS)
[✓] Promiscuous mode
[ ] Block offenders       ← ĐỂ TRỐNG (CrowdSec sẽ xử lý việc block)

Capture mode:   PCAP (live)

Pattern matcher: Hyperscan   ← nếu CPU Intel hỗ trợ
                 Aho-Corasick ← fallback nếu không có Hyperscan

Home networks:  <subnet LAN giữa OPNsense và Zimbra>
                Ví dụ: 10.0.0.0/24
                [chỉ khai báo LAN subnet, không khai báo WAN/Internet]

Interfaces:     LAN          ← interface giữa OPNsense và Zimbra VM
                             ← KHÔNG phải WAN (traffic WAN đã mã hóa TLS)
```

> ⚠️ **Không tick IPS Mode** — trên OpenStack/virtio sẽ gặp bug #10097, Divert không hoạt động. CrowdSec bouncer thay thế chức năng block.

> ⚠️ **Chọn đúng interface LAN** — Suricata phải sniff interface giữa HAProxy và Zimbra, nơi traffic đã được decrypt thành HTTP thuần. Sniff WAN chỉ thấy TLS encrypted, không đọc được URI/header.

### 1.3 Cài và chọn Rule Sets

`Services → Intrusion Detection → Download`

Tick các rule sets sau rồi click **"Download & Update Rules"**:

| Rule Set | Mục đích | Ghi chú |
|---|---|---|
| `et/open` | Bộ rule nền tảng | Miễn phí, update hàng ngày, dùng category `web_server`, `exploit`, `scan`, `malware` |
| `abuse.ch/urlhaus` | Block malicious URLs active | Bao gồm URL phishing/malware đang dùng |
| `abuse.ch/feodotracker` | C2 botnet IPs | HTTP C2 callback traffic |

> **Không dùng** `emerging-web_client` — category này bảo vệ browser client duyệt web, không liên quan đến mail server đứng nhận request.

### 1.4 Cấu hình Policy — Chỉ Alert, không Drop

`Services → Intrusion Detection → Policy → Add`

**Policy 1 — Alert Web Server Attacks:**
```
Priority:     1
Description:  Alert ET Web Server
Action:       Alert        ← KHÔNG chọn Drop (để CrowdSec xử lý)
Rules filter:
  Rulesets:   et/open
  Category:   emerging-web_server
```

**Policy 2 — Alert Exploits:**
```
Priority:     2
Description:  Alert Exploits
Action:       Alert
Rules filter:
  Rulesets:   et/open
  Category:   emerging-exploit
```

**Policy 3 — Alert Scan/Recon:**
```
Priority:     3
Description:  Alert Scan Recon
Action:       Alert
Rules filter:
  Rulesets:   et/open
  Category:   emerging-scan
```

**Policy 4 — Alert Malware C2:**
```
Priority:     4
Description:  Alert Malware C2
Action:       Alert
Rules filter:
  Rulesets:   et/open
  Category:   emerging-malware
```

> **Không tạo policy cho `emerging-web_client`** — category này detect mối đe dọa nhắm vào browser client duyệt web, không phù hợp với mail server đứng nhận request từ Internet.

### 1.5 Bật HTTP Logging trong EVE JSON

Cấu hình EVE JSON logging gồm 2 bước: **GUI** cho phần chuẩn, **SSH** cho phần XFF.

#### Bước A — Cấu hình qua GUI

`Services → Intrusion Detection → Administration → Logging Settings`

```
[✓] Enable syslog alerts
[✓] Enable eve syslog output
[✓] Enable eve HTTP logging          ← bật HTTP logging vào EVE JSON
[✓] Eve HTTP extended logging        ← log đầy đủ URI, method, status, referrer
Eve HTTP dump all headers:  Request  ← log TẤT CẢ request headers (bao gồm X-Forwarded-For)
[ ] Enable eve TLS logging           ← không cần (Suricata sniff LAN HTTP)
```

> **"Eve HTTP dump all headers → Request"** là bắt buộc trong kiến trúc này. Nếu để `None`, header `X-Forwarded-For` sẽ không xuất hiện trong EVE JSON → CrowdSec không đọc được IP thật attacker.

Sau khi cấu hình GUI → **Save**.

#### Bước B — Thêm XFF config qua SSH (không có trong GUI)

GUI không có option cho XFF extraction. Cần tạo file riêng để Suricata extract XFF thành trường `http.xff` độc lập trong EVE JSON — đây là trường CrowdSec parser đọc để lấy IP thật:

```bash
# SSH vào OPNsense
mkdir -p /usr/local/etc/suricata/conf.d/

cat > /usr/local/etc/suricata/conf.d/xff.yaml << 'EOF'
app-layer:
  protocols:
    http:
      xff:
        enabled: yes
        mode: extra-data     # tạo trường http.xff riêng trong EVE JSON
        deployment: reverse  # HAProxy là reverse proxy đứng trước
        header: X-Forwarded-For
EOF
```

**Sự khác nhau giữa GUI "dump all headers" và SSH xff config:**

| | GUI: dump all headers = Request | SSH: xff config |
|---|---|---|
| Tác dụng | Ghi XFF vào `request_headers[]` array | Ghi XFF vào trường `http.xff` riêng |
| CrowdSec đọc được? | ⚠️ Phải parse array phức tạp | ✅ Đọc trực tiếp `http.xff` |
| Dùng để | Debug thủ công, xem raw headers | CrowdSec tự động extract IP attacker |

→ **Cần cả hai**: GUI để log đầy đủ headers, SSH để CrowdSec hoạt động đúng.

### 1.6 Apply và kiểm tra Suricata

```
Services → Intrusion Detection → Administration → [Apply]
```

Kiểm tra qua SSH:

```bash
# Suricata đang chạy không?
ps aux | grep suricata

# EVE JSON có trường http.xff không? (sau khi có traffic HTTP)
tail -f /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'http' and 'xff' in e.get('http', {}):
            print('✅ XFF found:', e['http']['xff'])
            break
    except: pass
"

# Test config không có lỗi cú pháp
suricata -T -c /usr/local/etc/suricata/suricata.yaml -v 2>&1 | grep -E "error|warn|Loaded"
```

---

## Phần 2 — Custom Rules cho HTTP Zimbra

### 2.1 Hiểu kiến trúc traffic tại LAN interface

Suricata sniff tại LAN interface — sau HAProxy đã TLS termination — nên thấy HTTP thuần:

| Trường | Giá trị Suricata thấy | Ghi chú |
|---|---|---|
| `src_ip` | IP của HAProxy (LAN, vd: 10.0.0.1) | **Không phải** IP attacker |
| `dest_ip` | IP Zimbra (LAN, vd: 10.0.0.2) | |
| `http.uri` | `/zimbra/`, `/service/...` | ✅ Rõ ràng, full path |
| `http.method` | `GET`, `POST` | ✅ |
| `http.user_agent` | Browser, scanner UA | ✅ |
| `http.request_body` | POST body | ✅ |
| `http.header` → `X-Forwarded-For` | `203.0.113.1` | ✅ **IP thật attacker** |

**Hệ quả với rules:**
- Không dùng `$EXTERNAL_NET` → dùng `any` (src là HAProxy LAN IP)
- Không dùng `track by_src` trong threshold → dùng `track by_dst` hoặc track theo `X-Forwarded-For`
- CrowdSec **phải đọc XFF** để ban đúng IP attacker, không ban IP HAProxy

### 2.2 Cấu hình Suricata đọc X-Forwarded-For

XFF config đã được thực hiện ở **Phần 1.5 Bước B** (`conf.d/xff.yaml`). Sau khi apply, EVE JSON sẽ có trường `http.xff` chứa IP thật của attacker:

```json
{
  "src_ip": "10.0.0.1",
  "dest_ip": "10.0.0.2",
  "http": {
    "url": "/zimbra/",
    "http_method": "POST",
    "http_user_agent": "sqlmap/1.6",
    "xff": "203.0.113.1",
    "request_headers": [
      {"name": "X-Forwarded-For", "value": "203.0.113.1"},
      {"name": "X-Real-IP", "value": "203.0.113.1"}
    ]
  }
}
```

**CrowdSec parser `crowdsecurity/suricata-logs` sẽ đọc `http.xff` và ghi vào `evt.Meta.source_ip`** — đây là IP được dùng để ban tại WAN firewall, không phải `src_ip` (IP HAProxy).


### 2.3 Hiểu HTTP endpoints của Zimbra

| Endpoint | URL Pattern | Rủi ro chính |
|---|---|---|
| Webmail default | `/` hoặc `/zimbra/` | Brute force, credential stuffing |
| Webapp chính | `/zimbra/` | XSS, injection |
| Modern UI | `/modern/` | Injection |
| Classic UI | `/classic/` | XSS cũ |
| Admin console | `/zimbraAdmin/` | Unauthorized admin access |
| Service API | `/service/` | SSRF, API abuse |
| Service SOAP | `/service/soap/` | XXE, injection |
| PreAuth | `/service/preauth` | Token forging |
| Public assets | `/public/` | Thấp |
| ActiveSync | `/Microsoft-Server-ActiveSync` | Auth brute force |
| EWS | `/ews/Exchange.asmx` | Auth brute force, exploitation |
| Autodiscover | `/autodiscover/` | Information disclosure |

### 2.4 Custom Rules — Zimbra sau HAProxy (LAN interface)

`Services → Intrusion Detection → Rules → [Custom rules tab]`

Paste toàn bộ nội dung sau:

```
# ============================================================
# ZIMBRA HTTP SECURITY RULES — OPNsense 26.1
# Vị trí: LAN interface sau HAProxy (traffic HTTP đã decrypt)
# src_ip = HAProxy LAN IP → dùng "any" thay $EXTERNAL_NET
# IP thật attacker nằm trong X-Forwarded-For header
# Action: "alert" — CrowdSec xử lý block qua XFF
# SID range: 9001000 - 9001099
# ============================================================

# -----------------------------------------------------------
# NHÓM 1: ADMIN CONSOLE
# -----------------------------------------------------------

# Admin console không bao giờ nên accessible qua public proxy
# HAProxy nên block ở tầng trên, rule này là lớp backup
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA Admin Console Access via Proxy"; \
  flow:established,to_server; \
  http.uri; content:"/zimbraAdmin/"; startswith; \
  classtype:web-application-attack; \
  sid:9001001; rev:1;)

# -----------------------------------------------------------
# NHÓM 2: BRUTE FORCE / CREDENTIAL STUFFING
# -----------------------------------------------------------

# Login brute force — POST nhiều lần vào /zimbra/
# threshold track by_dst vì src luôn là HAProxy LAN IP
# CrowdSec sẽ đọc XFF để ban đúng IP
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA Webmail Login Brute Force"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.uri; content:"/zimbra/"; \
  threshold:type threshold,track by_dst,count 20,seconds 60; \
  classtype:attempted-user; \
  sid:9001002; rev:1;)

# ActiveSync brute force — thiết bị mobile
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA ActiveSync Brute Force"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.uri; content:"/Microsoft-Server-ActiveSync"; \
  threshold:type threshold,track by_dst,count 10,seconds 30; \
  classtype:attempted-user; \
  sid:9001003; rev:1;)

# EWS brute force — Outlook/client desktop
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA EWS Brute Force"; \
  flow:established,to_server; \
  http.uri; content:"/ews/Exchange.asmx"; \
  threshold:type threshold,track by_dst,count 20,seconds 60; \
  classtype:attempted-user; \
  sid:9001004; rev:1;)

# -----------------------------------------------------------
# NHÓM 3: INJECTION ATTACKS
# -----------------------------------------------------------

# SQL Injection trong URI — bất kỳ endpoint Zimbra
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA SQL Injection in URI"; \
  flow:established,to_server; \
  http.uri; pcre:"/(\%27|\x27)\s*(OR|AND|UNION|SELECT|INSERT|DROP|UPDATE|DELETE)/i"; \
  classtype:web-application-attack; \
  sid:9001010; rev:1;)

# XSS trong URI
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA XSS Attempt in URI"; \
  flow:established,to_server; \
  http.uri; pcre:"/(<script[\s>]|javascript:|on(load|error|click|mouse)\s*=)/i"; \
  classtype:web-application-attack; \
  sid:9001011; rev:1;)

# XSS trong POST body (form submission)
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA XSS in POST Body"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.request_body; pcre:"/(<script[\s>]|javascript:|on(load|error|click)\s*=)/i"; \
  classtype:web-application-attack; \
  sid:9001012; rev:1;)

# SOAP/XML Injection vào service endpoint
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA SOAP Injection Attempt"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.uri; content:"/service/soap/"; \
  http.request_body; pcre:"/(<!ENTITY|SYSTEM\s+[\"']|file:\/\/|expect:\/\/)/i"; \
  classtype:web-application-attack; \
  sid:9001013; rev:1;)

# -----------------------------------------------------------
# NHÓM 4: PATH TRAVERSAL & FILE INCLUSION
# -----------------------------------------------------------

# Path traversal trong URI
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA Path Traversal Attempt"; \
  flow:established,to_server; \
  http.uri; pcre:"/(\.\.[\/\\]){2,}/"; \
  classtype:web-application-attack; \
  sid:9001020; rev:1;)

# Path traversal encoded
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA Encoded Path Traversal"; \
  flow:established,to_server; \
  http.uri; pcre:"/(%2e%2e[%2f%5c]|%252e%252e)/i"; \
  classtype:web-application-attack; \
  sid:9001021; rev:1;)

# -----------------------------------------------------------
# NHÓM 5: SSRF
# -----------------------------------------------------------

# SSRF qua /service/proxy — redirect về internal
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA SSRF via Service Proxy"; \
  flow:established,to_server; \
  http.uri; content:"/service/proxy"; \
  http.uri; pcre:"/(127\.0\.0\.1|localhost|169\.254\.|10\.\d+\.\d+\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i"; \
  classtype:web-application-attack; \
  sid:9001030; rev:1;)

# SSRF qua /service/home — file fetching
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA SSRF via Service Home"; \
  flow:established,to_server; \
  http.uri; content:"/service/home/"; \
  http.uri; pcre:"/(file:\/\/|dict:\/\/|gopher:\/\/|ftp:\/\/)/i"; \
  classtype:web-application-attack; \
  sid:9001031; rev:1;)

# -----------------------------------------------------------
# NHÓM 6: WEBSHELL & RCE
# -----------------------------------------------------------

# WebShell upload trong POST body
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA WebShell Upload Attempt"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.request_body; pcre:"/(eval\s*\(base64_decode|system\s*\(\$_(GET|POST|REQUEST)|passthru\s*\(|shell_exec\s*\(|popen\s*\()/i"; \
  classtype:trojan-activity; \
  sid:9001040; rev:1;)

# PreAuth token manipulation
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA PreAuth Token Manipulation"; \
  flow:established,to_server; \
  http.uri; content:"/service/preauth"; \
  http.uri; pcre:"/[<>\"']|(\.\.[\/\\])/"; \
  classtype:web-application-attack; \
  sid:9001041; rev:1;)

# -----------------------------------------------------------
# NHÓM 7: SCANNER & RECON
# -----------------------------------------------------------

# Scanner User-Agent phổ biến
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA Web Scanner User-Agent"; \
  flow:established,to_server; \
  http.user_agent; pcre:"/sqlmap|nuclei|nikto|dirbuster|gobuster|ffuf|wfuzz|masscan|nmap|ZimbraScanner/i"; \
  classtype:web-application-attack; \
  sid:9001050; rev:1;)

# Directory enumeration — nhiều request 404 liên tiếp
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA Directory Enumeration"; \
  flow:established,to_server; \
  http.uri; pcre:"/(\.env|\.git|\.htaccess|wp-admin|phpmyadmin|adminer|backup|\.sql|\.bak)/i"; \
  classtype:web-application-attack; \
  sid:9001051; rev:1;)

# Autodiscover abuse — information disclosure
alert http any any -> $HTTP_SERVERS 80 \
  (msg:"ZIMBRA Autodiscover Probe"; \
  flow:established,to_server; \
  http.uri; pcre:"/\/(autodiscover|Autodiscover)\//i"; \
  http.method; content:"POST"; \
  threshold:type threshold,track by_dst,count 10,seconds 60; \
  classtype:policy-violation; \
  sid:9001052; rev:1;)
```

> **Lưu ý sau khi paste**: click **Save** → `Services → Intrusion Detection → Administration → [Apply]`

### 2.5 Giải thích các quyết định thiết kế rule

**Dùng `any any` thay vì `$EXTERNAL_NET any`:**
Vì src_ip Suricata thấy là IP HAProxy (LAN), không phải Internet. Dùng `$EXTERNAL_NET` sẽ không match.

**Dùng `track by_dst` trong threshold thay vì `track by_src`:**
Vì tất cả request đều từ cùng 1 src (HAProxy). Track by_dst (Zimbra) đếm tổng request đến — kết hợp với CrowdSec đọc XFF để xác định IP thật.

**Không dùng threshold cho injection/traversal/webshell:**
1 request duy nhất đã là attack → alert ngay, không cần threshold.

**Threshold cao hơn thực tế:**
User hợp lệ kiểm email ActiveSync mỗi vài giây → threshold phải đủ cao để không false positive. CrowdSec scenario sẽ lọc thêm.

### 2.6 Kiểm tra rule đã load

```bash
# Đếm custom rules đã load
grep -c "ZIMBRA\|Scanner" /usr/local/etc/suricata/opnsense.rules/OPNsense.rules

# Test config không lỗi cú pháp
suricata -T -c /usr/local/etc/suricata/suricata.yaml -v 2>&1 | grep -E "error|warn"

# Xem rule nào đang active cho port 80
suricatasc -c ruleset-stats
```

---


## Phần 3 — Tích hợp CrowdSec đọc Suricata EVE + X-Forwarded-For

> Phần này giả định CrowdSec đã được cài và bouncer pf đã active trên OPNsense.

### 3.1 Vấn đề XFF và cách CrowdSec xử lý

Trong kiến trúc HAProxy → LAN → Zimbra, EVE JSON có dạng:

```json
{
  "src_ip": "10.0.0.1",        ← IP HAProxy — KHÔNG ban cái này
  "dest_ip": "10.0.0.2",
  "http": {
    "xff": "203.0.113.1",      ← IP thật attacker — ban cái này
    "url": "/zimbra/",
    "http_user_agent": "sqlmap/1.6"
  },
  "alert": {
    "signature": "ZIMBRA Web Scanner User-Agent",
    "category": "web-application-attack"
  }
}
```

CrowdSec parser `crowdsecurity/suricata-logs` **có hỗ trợ XFF** — nó ghi IP từ `http.xff` vào `evt.Meta.source_ip` thay vì `src_ip` khi XFF có mặt. Điều này đảm bảo bouncer ban đúng IP attacker trên WAN firewall.

### 3.2 Khai báo datasource Suricata EVE

```bash
cat > /usr/local/etc/crowdsec/acquis.d/suricata.yaml << 'EOF'
filenames:
  - /var/log/suricata/eve.json
labels:
  type: suricata_evelog
EOF
```

### 3.3 Cài Suricata collection

```bash
cscli collections install crowdsecurity/suricata

# Kiểm tra đã cài
cscli collections list | grep suricata
```

Collection bao gồm:

| Component | Chức năng |
|---|---|
| `crowdsecurity/suricata-logs` | Parser: đọc EVE JSON, ưu tiên XFF làm source_ip |
| `crowdsecurity/suricata-major-severity` | Scenario: ban khi alert severity = major |
| `crowdsecurity/suricata-critical-severity` | Scenario: ban khi alert severity = critical |

### 3.4 Reload và kiểm tra XFF được parse đúng

```bash
service crowdsec reload

# Kiểm tra acquisition
cscli metrics show acquisition
```

Sau đó trigger 1 alert test (từ ngoài Internet qua HAProxy):
```bash
curl -A "sqlmap/1.6.0" https://mail.domain.com/zimbra/
```

Kiểm tra CrowdSec đọc đúng IP attacker (không phải HAProxy):
```bash
# Xem alert vừa tạo — source_ip phải là IP Internet, không phải LAN
cscli alerts list --since 5m

# Nếu source_ip vẫn là IP HAProxy → XFF chưa được parse
# Kiểm tra trường xff trong EVE JSON
tail -f /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            xff = e.get('http', {}).get('xff', 'KHÔNG CÓ XFF')
            src = e.get('src_ip')
            print(f'src_ip={src}  xff={xff}  sig={e[\"alert\"][\"signature\"]}')
    except: pass
"
```

> Nếu `xff = KHÔNG CÓ XFF` → kiểm tra lại cấu hình XFF trong Suricata (Phần 2.2) và xác nhận HAProxy đang gửi header `X-Forwarded-For`.

### 3.5 Scenario — Zimbra HTTP Attack (XFF-aware)

```bash
mkdir -p /usr/local/etc/crowdsec/scenarios/

cat > /usr/local/etc/crowdsec/scenarios/zimbra-http-attack.yaml << 'EOF'
type: leaky
name: local/zimbra-http-attack
description: "Block IPs triggering Zimbra HTTP attack signatures — reads XFF for real attacker IP"
filter: >
  evt.Meta.log_type == 'suricata_eve' &&
  evt.Meta.alert_category in ['web-application-attack', 'trojan-activity'] &&
  evt.Meta.source_ip != '' &&
  evt.Meta.source_ip != '10.0.0.1'
leakspeed: "30s"
capacity: 3
groupby: evt.Meta.source_ip
blackhole: 5m
labels:
  service: zimbra
  type: http_attack
  remediation: true
EOF
```

> **Lưu ý dòng `evt.Meta.source_ip != '10.0.0.1'`**: Thay `10.0.0.1` bằng IP thực của HAProxy. Đây là safety net — nếu XFF không được parse, tránh ban nhầm HAProxy.

### 3.6 Scenario — Zimbra Brute Force (XFF-aware)

```bash
cat > /usr/local/etc/crowdsec/scenarios/zimbra-bruteforce.yaml << 'EOF'
type: leaky
name: local/zimbra-bruteforce
description: "Block brute force on Zimbra login/ActiveSync/EWS — reads XFF"
filter: >
  evt.Meta.log_type == 'suricata_eve' &&
  (evt.Meta.alert_signature contains 'Brute Force' ||
   evt.Meta.alert_signature contains 'ActiveSync' ||
   evt.Meta.alert_signature contains 'EWS') &&
  evt.Meta.source_ip != '' &&
  evt.Meta.source_ip != '10.0.0.1'
leakspeed: "10s"
capacity: 5
groupby: evt.Meta.source_ip
blackhole: 10m
labels:
  service: zimbra
  type: bruteforce
  remediation: true
EOF
```

### 3.7 Scenario — Zimbra Critical (1-shot ban: WebShell, SSRF, RCE)

Các attack này cần ban ngay lập tức không cần đợi đủ capacity:

```bash
cat > /usr/local/etc/crowdsec/scenarios/zimbra-critical.yaml << 'EOF'
type: trigger
name: local/zimbra-critical
description: "Immediate ban for critical Zimbra attacks: WebShell, SSRF, RCE"
filter: >
  evt.Meta.log_type == 'suricata_eve' &&
  (evt.Meta.alert_signature contains 'WebShell' ||
   evt.Meta.alert_signature contains 'SSRF' ||
   evt.Meta.alert_signature contains 'RCE' ||
   evt.Meta.alert_category == 'trojan-activity') &&
  evt.Meta.source_ip != '' &&
  evt.Meta.source_ip != '10.0.0.1'
groupby: evt.Meta.source_ip
blackhole: 1h
labels:
  service: zimbra
  type: critical
  remediation: true
EOF
```

**Dùng `type: trigger`** — 1 alert duy nhất = ban ngay, không cần leaky bucket.

### 3.8 Reload và kiểm tra scenarios

```bash
service crowdsec reload

# Kiểm tra scenarios đã load
cscli scenarios list | grep -E "suricata|zimbra"

# Output mong đợi:
# crowdsecurity/suricata-major-severity      ✅ enabled
# crowdsecurity/suricata-critical-severity   ✅ enabled
# local/zimbra-http-attack                   ✅ enabled
# local/zimbra-bruteforce                    ✅ enabled
# local/zimbra-critical                      ✅ enabled
```

---


## Phần 4 — Kiểm tra toàn bộ pipeline

### 4.1 Test end-to-end

Từ máy test bên ngoài (hoặc dùng `curl` qua proxy):

```bash
# Test 1: Scanner detection
curl -v -A "sqlmap/1.6.0" http://YOUR-ZIMBRA-IP/zimbra/

# Test 2: Admin console access
curl -v http://YOUR-ZIMBRA-IP/zimbraAdmin/

# Test 3: Path traversal
curl -v "http://YOUR-ZIMBRA-IP/zimbra/../etc/passwd"
```

### 4.2 Xem Suricata alert

```bash
# Theo dõi alert realtime
tail -f /var/log/suricata/eve.json | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            print(f\"[ALERT] {e['src_ip']} → {e['alert']['signature']}\")
    except: pass
"
```

### 4.3 Xem CrowdSec đang xử lý

```bash
# Decisions đang active (IP bị ban)
cscli decisions list

# Alert từ Suricata (1 giờ qua)
cscli alerts list --since 1h

# Metrics tổng hợp
cscli metrics show scenarios
```

### 4.4 Test thực tế — trigger ban

```bash
# Gửi nhiều request để trigger scenario (capacity=3)
for i in {1..10}; do
  curl -s -A "sqlmap/1.6.0" http://YOUR-ZIMBRA-IP/zimbra/ > /dev/null
  sleep 1
done

# Sau đó kiểm tra IP test có bị ban không
cscli decisions list
```

---

## Phần 5 — Vận hành và Monitoring

### 5.1 Xem alerts Suricata trong OPNsense GUI

`Services → Intrusion Detection → Alerts`

- Filter theo **Signature ID** (9001xxx = Zimbra custom rules)
- Cột Interface có thể trống (known cosmetic bug #9683) — alert vẫn hoạt động
- Click **ⓘ** để xem full EVE JSON

### 5.2 Quản lý CrowdSec decisions

```bash
# Xem IP đang bị ban
cscli decisions list

# Unblock IP bị ban nhầm
cscli decisions delete --ip 1.2.3.4

# Whitelist IP vĩnh viễn (không bao giờ bị ban)
cscli allowlists add trusted --value 1.2.3.4 --comment "Internal scanner"

# Block thủ công 1 IP
cscli decisions add --ip 5.6.7.8 --duration 24h --reason "Manual block"
```

### 5.3 Suppress false positive trong Suricata

`Services → Intrusion Detection → Administration → Suppress list`

```
type:    src
ip:      1.2.3.4    ← IP bị false positive
sid:     9001002    ← SID của rule gây ra
```

Hoặc qua SSH:
```bash
# Thêm vào threshold.config
echo 'suppress gen_id 1, sig_id 9001002, track by_src, ip 1.2.3.4' \
  >> /usr/local/etc/suricata/threshold.config
```

### 5.4 Update rules định kỳ

```bash
# Cập nhật Suricata rules (chạy hàng ngày qua cron)
# OPNsense tự update nếu đã cấu hình trong GUI

# Cập nhật CrowdSec hub (scenarios, parsers)
cscli hub update
cscli hub upgrade
service crowdsec reload
```

### 5.5 Monitoring commands thường dùng

```bash
# Suricata stats
suricatasc -c dump-counters | grep -E "capture|drop|decode"

# EVE JSON stats theo event_type
cat /var/log/suricata/eve.json | \
  python3 -c "
import sys, json
from collections import Counter
c = Counter()
for l in sys.stdin:
    try: c[json.loads(l).get('event_type','?')] += 1
    except: pass
for k,v in c.most_common(): print(f'{v:>8} {k}')
"

# CrowdSec tổng quan
cscli metrics
```

---

## Phần 6 — Xử lý lỗi thường gặp

| Triệu chứng | Nguyên nhân | Giải pháp |
|---|---|---|
| Suricata không start | Cú pháp rule sai | `suricata -T -c /usr/local/etc/suricata/suricata.yaml -v` |
| Không có alert nào | Sai interface, HOME_NET chưa đúng | Kiểm tra `vars.address-groups` trong suricata.yaml |
| EVE JSON trống | Suricata chưa thấy traffic | `tcpdump -i vtnet0 port 80` để verify traffic vào interface |
| CrowdSec không đọc EVE | File path sai hoặc permission | `ls -la /var/log/suricata/eve.json` — phải readable bởi crowdsec |
| `Lines parsed = 0` | Parser suricata chưa load | `cscli collections install crowdsecurity/suricata` rồi reload |
| Scenario không trigger | Threshold chưa đủ | Tăng request test, giảm `capacity` trong scenario |
| IP bị ban nhầm | False positive rule | Dùng `cscli decisions delete` + thêm allowlist |
| `ipfw list` trống | Bug #10097 (OpenStack virtio) | Đây là expected — IDS + CrowdSec bouncer thay thế |

### Kiểm tra pipeline khi không có alert

```bash
# Bước 1: Traffic vào interface không?
tcpdump -i vtnet0 -n port 80 -c 10

# Bước 2: Suricata thấy traffic không?
suricatasc -c dump-counters | grep "capture.kernel_packets"

# Bước 3: Rules có load đủ không?
suricatasc -c ruleset-stats | grep total

# Bước 4: Test rule với packet đơn giản
echo 'alert http any any -> any any (msg:"TEST"; http.uri; content:"/zimbra"; sid:9999999; rev:1;)' \
  > /tmp/test.rules
suricata -T -S /tmp/test.rules -c /usr/local/etc/suricata/suricata.yaml

# Bước 5: CrowdSec nhận data không?
cscli metrics show acquisition
```

---

## Phần 7 — Cấu trúc file tham khảo

```
/usr/local/etc/suricata/
├── suricata.yaml                    ← generated bởi OPNsense, KHÔNG sửa tay
├── conf.d/
│   └── xff.yaml                     ← XFF extraction config (Phần 1.5B — SSH)
├── opnsense.rules/
│   ├── OPNsense.rules               ← custom Zimbra rules (Phần 2.4)
│   ├── et.emerging-web_server.rules
│   ├── et.emerging-exploit.rules
│   ├── et.emerging-scan.rules
│   └── et.emerging-malware.rules
└── threshold.config                 ← suppress rules

/usr/local/etc/crowdsec/
├── acquis.d/
│   └── suricata.yaml                ← datasource EVE JSON (Phần 3.2)
├── scenarios/
│   ├── zimbra-http-attack.yaml      ← leaky bucket, capacity=3 (Phần 3.5)
│   ├── zimbra-bruteforce.yaml       ← leaky bucket, capacity=5 (Phần 3.6)
│   └── zimbra-critical.yaml         ← trigger, ban ngay (Phần 3.7)
└── config.yaml                      ← config chính CrowdSec

/var/log/suricata/
└── eve.json                         ← EVE JSON output, có trường http.xff
```

---

## Checklist triển khai

```
PHẦN 1 — Suricata cơ bản
[ ] Hardware offloading đã tắt (Interfaces → Settings)
[ ] Suricata bật PCAP mode, IPS mode BỎ TICK, Block offenders BỎ TICK
[ ] Sniff đúng LAN interface (interface giữa OPNsense và Zimbra VM)
[ ] Rule sets et/open, abuse.ch/urlhaus, abuse.ch/feodotracker đã download
[ ] Policy Alert: emerging-web_server, emerging-exploit, emerging-scan, emerging-malware
[ ] KHÔNG tạo policy cho emerging-web_client

PHẦN 1.5 — EVE JSON Logging
[ ] GUI: Enable eve HTTP logging ✅, Eve HTTP extended logging ✅
[ ] GUI: Eve HTTP dump all headers → "Request" (không phải None)
[ ] SSH: /usr/local/etc/suricata/conf.d/xff.yaml đã tạo
[ ] Apply trong GUI → Suricata reload
[ ] suricata -T không có lỗi cú pháp
[ ] Verify EVE JSON có http.xff = IP Internet (không phải HAProxy LAN)

PHẦN 2 — Custom Rules
[ ] Custom Zimbra rules đã paste (7 nhóm, any any -> $HTTP_SERVERS 80)
[ ] threshold dùng track by_dst (không phải by_src)
[ ] Apply → kiểm tra rule count

PHẦN 3 — CrowdSec
[ ] acquis.d/suricata.yaml đã tạo
[ ] crowdsecurity/suricata collection đã cài
[ ] 3 scenarios đã tạo: zimbra-http-attack, zimbra-bruteforce, zimbra-critical
[ ] IP HAProxy đã khai báo trong filter scenarios (safety net)
[ ] service crowdsec reload
[ ] cscli metrics show acquisition → Lines parsed > 0
[ ] cscli alerts list → source_ip là IP Internet

KIỂM TRA END-TO-END
[ ] curl -A "sqlmap/1.6" https://mail.domain.com/zimbra/ → Suricata alert
[ ] EVE JSON: http.xff = IP máy test (Internet IP)
[ ] CrowdSec alert: source_ip = IP máy test
[ ] cscli decisions list → IP máy test bị ban
[ ] Truy cập từ IP máy test bị block tại WAN firewall
```

---

## Tham khảo

| Tài liệu | URL |
|---|---|
| Suricata HTTP Keywords | https://docs.suricata.io/en/latest/rules/http-keywords.html |
| Suricata EVE JSON | https://docs.suricata.io/en/latest/output/eve/eve-json-format.html |
| Suricata XFF Config | https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#x-forwarded-for |
| CrowdSec Scenario Reference | https://docs.crowdsec.net/docs/scenarios/format |
| CrowdSec Acquisition | https://docs.crowdsec.net/docs/data_sources/file |
| OPNsense IDS Manual | https://docs.opnsense.org/manual/ips.html |
| OPNsense 26.1 Release Notes | https://docs.opnsense.org/releases/CE_26.1.html |
| Bug #10097 (Divert IPS virtio) | https://github.com/opnsense/core/issues/10097 |
| Zimbra Security Advisories | https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories |
