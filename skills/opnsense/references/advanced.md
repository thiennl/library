# OPNsense Advanced Topics

## HAProxy — Reverse Proxy & Load Balancer

### Use Cases
- Expose nhiều web services ra ngoài qua 1 IP (SNI-based routing)
- SSL termination (offload HTTPS từ backend servers)
- Load balancing giữa nhiều servers
- Health checking — tự động loại server chết khỏi pool

### Cấu hình hoàn chỉnh (ví dụ: 2 web apps qua domain)

**Scenario**: 
- `app1.example.com` → `192.168.1.10:8080`
- `app2.example.com` → `192.168.1.11:8080`
- OPNsense nhận HTTPS :443 từ WAN, SNI routing vào backend

**Bước 1: Real Servers**
```
Services → HAProxy → Real Servers → Add
  Name: app1_server
  IP/Hostname: 192.168.1.10
  Port: 8080
  Mode: active
  Health Check: HTTP
  Health Check URL: /health

Services → HAProxy → Real Servers → Add
  Name: app2_server
  IP/Hostname: 192.168.1.11
  Port: 8080
```

**Bước 2: Backend Pools**
```
Services → HAProxy → Backend Pools → Add
  Name: app1_pool
  Balance: roundrobin (hoặc leastconn)
  Servers: app1_server

Services → HAProxy → Backend Pools → Add
  Name: app2_pool
  Servers: app2_server
```

**Bước 3: Conditions & Rules**
```
Services → HAProxy → Rules & Checks → Conditions → Add
  Name: is_app1
  Condition type: SNI TLS extension matches
  Value: app1.example.com

Services → HAProxy → Rules & Checks → Rules → Add
  Name: route_app1
  Select conditions: is_app1
  Execute function: Use specified Backend Pool
  Backend Pool: app1_pool
```

**Bước 4: Frontend**
```
Services → HAProxy → Frontend → Add
  Name: https_frontend
  Listen address: WAN_IP:443
  SSL Offloading: ✓
  Certificates: [chọn cert wildcard hoặc multi-SAN]
  Default Backend Pool: app1_pool (fallback)
  Rules: route_app1, route_app2
```

**Firewall rule cần thêm**:
```
WAN → allow TCP 443 → WAN address
```

📖 Ref: https://docs.opnsense.org/manual/proxy.html

---

## Captive Portal

Chặn truy cập Internet, yêu cầu user authenticate trước (dùng trong WiFi guest, hotel, v.v.).

```
Services → Captive Portal → Templates → Add
  [Upload custom HTML/CSS template nếu muốn branded]

Services → Captive Portal → Zones → Add
  Interfaces: VLAN_GUEST
  Auth Method: Local User Database / Vouchers / RADIUS
  Idle Timeout: 30 minutes
  Hard Timeout: 8 hours
  Bandwidth Up: 10 Mbps
  Bandwidth Down: 20 Mbps
```

📖 Ref: https://docs.opnsense.org/manual/captiveportal.html

---

## Traffic Shaping (QoS)

Giới hạn và ưu tiên bandwidth theo loại traffic.

**Firewall → Shaper → Pipes** (định nghĩa bandwidth limits)
**Firewall → Shaper → Queues** (tạo queues với priority)
**Firewall → Shaper → Rules** (assign traffic vào queues)

```
Ví dụ: Ưu tiên VoIP traffic
  Pipe: WAN_OUT_100M (100 Mbps)
  Queue: VOIP_Q (priority: high, weight: 100)
  Queue: BULK_Q (priority: low, weight: 10)
  Rule: match UDP dst port 5060 → VOIP_Q
  Rule: match everything else → BULK_Q
```

📖 Ref: https://docs.opnsense.org/manual/shaper.html

---

## Suricata Advanced

### Custom Rules (26.1 — conf.d method)

```bash
# Tạo custom rule file
cat > /usr/local/etc/suricata/conf.d/custom-rules.yaml << 'YAML'
rule-files:
  - /usr/local/etc/suricata/rules/custom.rules
YAML

# Tạo rule
cat > /usr/local/etc/suricata/rules/custom.rules << 'RULES'
# Block known malicious UA
alert http any any -> any any (
  msg:"Suspicious User-Agent";
  http.user_agent;
  content:"evil-scanner/1.0";
  sid:9000001;
  rev:1;
)
RULES

# Reload Suricata
pluginctl -s ids start
```

### Eve.json Analysis

```bash
# Top IPs bị alert
cat /var/log/suricata/eve.json | \
  python3 -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            c[e['src_ip']] += 1
    except: pass
for ip, cnt in c.most_common(10):
    print(f'{cnt:5d} {ip}')
"
```

---

## OPNsense API — Ansible Integration

```yaml
# ansible/tasks/opnsense_alias.yml
- name: Create firewall alias
  uri:
    url: "https://{{ opnsense_host }}/api/firewall/alias/addItem"
    method: POST
    user: "{{ api_key }}"
    password: "{{ api_secret }}"
    validate_certs: no
    body_format: json
    body:
      alias:
        name: "MY_SERVERS"
        type: "host"
        content: "192.168.1.10\n192.168.1.11"
        description: "Application servers"
  register: result

- name: Apply alias changes
  uri:
    url: "https://{{ opnsense_host }}/api/firewall/alias/reconfigure"
    method: POST
    user: "{{ api_key }}"
    password: "{{ api_secret }}"
    validate_certs: no
```

---

## Performance Tuning

### Netmap / DPDK (high throughput)

OPNsense hỗ trợ **netmap** cho high-speed packet processing (bypass kernel stack một phần).
Chỉ cần với throughput > 1 Gbps hoặc nhiều triệu packets/sec.

```bash
# Kiểm tra NIC hỗ trợ netmap
kldstat | grep netmap
# Load nếu chưa có
kldload netmap
```

### Sysctl Tuning

```bash
# /etc/sysctl.conf (persistent) hoặc qua GUI: System → Settings → Tunables

# Tăng pf state table
net.pf.states_hashsize=4194304
kern.ipc.maxsockbuf=16777216

# Buffer network
net.inet.tcp.sendbuf_max=16777216
net.inet.tcp.recvbuf_max=16777216

# UDP buffer cho WireGuard/IPsec
net.inet.udp.maxdgram=65536
```

---

## Backup & Restore Script

```bash
#!/bin/sh
# Chạy trên OPNsense để backup config tự động
BACKUP_DIR="/mnt/nas/opnsense-backups"
DATE=$(date +%Y%m%d-%H%M%S)
HOSTNAME=$(hostname)

cp /conf/config.xml "$BACKUP_DIR/${HOSTNAME}-${DATE}.xml"

# Giữ lại 30 bản gần nhất
ls -t "$BACKUP_DIR/${HOSTNAME}-"*.xml | tail -n +31 | xargs rm -f

echo "Backup done: ${HOSTNAME}-${DATE}.xml"
```

Thêm vào cron: **System → Settings → Cron** → Add (chạy lúc 2:00 AM hàng ngày).