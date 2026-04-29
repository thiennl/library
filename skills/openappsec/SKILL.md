---
name: openappsec
description: >
  Hướng dẫn chuyên sâu về open-appsec WAF/API Security với vai trò mentor senior — từ lý thuyết đến thực chiến. Kích hoạt skill này khi người dùng hỏi về: cài đặt, cấu hình, troubleshooting open-appsec; WAF machine learning; deploy open-appsec trên Linux/Docker/Kubernetes; policy file YAML; phòng chống OWASP Top-10 / zero-day; tích hợp NGINX/Kong/APISIX; so sánh open-appsec với WAF truyền thống; tuning ML engine; API schema enforcement; anti-bot; IPS/DLP trong open-appsec. Luôn dùng skill này bất cứ khi nào người dùng đề cập "open-appsec", "WAF ML", "appsec-ctl", "openappsec", "appsec agent", "appsec policy", hoặc bất kỳ câu hỏi nào liên quan bảo mật ứng dụng web tự động hóa.
---

# open-appsec Mentor — Từ Lý Thuyết Đến Thực Chiến

## Triết lý hướng dẫn

Trả lời theo phong cách **mentor senior**: giải thích *tại sao* trước khi nói *làm thế nào*. Dùng ngôn ngữ đơn giản cho khái niệm phức tạp. Tham chiếu docs official (docs.openappsec.io). Không tự sáng tạo thông tin — chỉ nói những gì có căn cứ.

---

## PHẦN 1: NỀN TẢNG KHÁI NIỆM

### 1.1 open-appsec là gì? (Giải thích như cho người mới)

Hãy tưởng tượng bạn có một người bảo vệ thông minh đứng trước cửa ứng dụng web. WAF truyền thống giống một bảo vệ cầm danh sách đen (blacklist) — chỉ chặn những ai có tên trong danh sách. Kẻ tấn công mới? Vào thoải mái vì chưa có trong danh sách.

**open-appsec** giống bảo vệ được huấn luyện bằng AI — học cách người dùng hợp lệ thường hành xử, rồi tự phán đoán request lạ có nguy hiểm không, dù chưa từng gặp kiểu tấn công đó bao giờ.

> 📖 **Nguồn**: [What is open-appsec?](https://docs.openappsec.io/what-is-open-appsec)

**Định nghĩa chính thức**: open-appsec là open-source, fully automated Web Application and API Security solution, được vận hành bởi machine learning engine liên tục phân tích HTTP/S requests.

**Điểm khác biệt cốt lõi so với WAF truyền thống**:
| Tiêu chí | WAF truyền thống | open-appsec |
|----------|-----------------|-------------|
| Cơ chế phát hiện | Signature/Rule-based | Machine Learning |
| Zero-day attack | ❌ Không bảo vệ | ✅ Chặn được |
| Tuning/exception | Thủ công, tốn công | Tự động học |
| False positive | Cao nếu misconfigure | Thấp hơn đáng kể |
| Log4Shell 0-day | Cần cập nhật signature | Chặn được ngay |

---

### 1.2 Kiến trúc Agent — "Bộ não và tay chân"

> 📖 **Nguồn**: [Machine Learning Engine — Technology](https://www.openappsec.io/tech)

open-appsec Agent gồm 4 thành phần, hiểu đúng giúp troubleshoot tốt hơn:

```
┌─────────────────────────────────────────────────────┐
│                   open-appsec Agent                  │
│                                                     │
│  ┌─────────────┐  ┌──────────────────────────────┐  │
│  │ Attachment  │  │   HTTP Transaction Handler   │  │
│  │ (Connector) │→ │   (Security Logic / Verdict) │  │
│  └─────────────┘  └──────────────────────────────┘  │
│                                                     │
│  ┌──────────────┐  ┌──────────┐                    │
│  │ Orchestrator │  │ Watchdog │                    │
│  │(Policy/Update│  │(Keep-    │                    │
│  │  /Register) │  │ alive)   │                    │
│  └──────────────┘  └──────────┘                    │
└─────────────────────────────────────────────────────┘
```

- **Attachment**: Cầu nối giữa NGINX/Kong/APISIX và security logic. Open source, do Check Point cung cấp.
- **HTTP Transaction Handler**: Tiếp nhận data từ Attachment, chạy AppSec logic, trả về verdict (allow/block), ghi log.
- **Orchestrator**: Đăng ký agent, nhận policy update, software update, quản trị.
- **Watchdog**: Giám sát các component, restart nếu crash.

**Trong Kubernetes**: ingress controller có sidecar container chạy open-appsec security inspection.

---

### 1.3 Contextual Machine Learning Engine — Trái tim hệ thống

> 📖 **Nguồn**: [Contextual Machine Learning](https://docs.openappsec.io/concepts/contextual-machine-learning)

Đây là điểm then chốt nhất để hiểu tại sao open-appsec hoạt động tốt.

**Hai model ML song song**:

```
                HTTP Request đến
                      │
                      ▼
         ┌────────────────────────┐
         │  Phase 1: Parse &      │
         │  Decode Payload        │
         │  (URL, headers, JSON,  │
         │   XML, base64 decode)  │
         └───────────┬────────────┘
                     │
                     ▼
         ┌────────────────────────┐
         │  Phase 2: Attack       │
         │  Indicators Search     │
         │  (Supervised Model:    │
         │   trained offline với  │
         │   millions requests)   │
         └───────────┬────────────┘
                     │
              ┌──────┴──────┐
              │ Suspicious? │
              └──────┬──────┘
          No (benign)│        Yes
              ▼      │          ▼
           ALLOW     │   Phase 3: Contextual
                     │   Evaluation Engine
                     │   (Unsupervised Model:
                     │    học từ traffic thực
                     │    tế của môi trường)
                     │          │
                     │   Final Confidence Score
                     │    ALLOW / BLOCK
```

**Supervised Model** — học offline:
- Được train với hàng triệu malicious + benign requests
- Phát hiện attack indicators theo các "gia đình" tấn công
- Có hai phiên bản: **Basic Model** (GitHub, dùng cho test) và **Advanced Model** (download từ portal, dùng cho production)

**Unsupervised Model** — học real-time tại chỗ:
- Xây dựng ngay trong môi trường được bảo vệ
- Học pattern bình thường của traffic thực: URL nào, user nào, tần suất thế nào
- Kết hợp với supervised model tạo ra final verdict với confidence score

**Tại sao cần cả hai?** Supervised model biết "attack trông như thế nào trên toàn thế giới", unsupervised model biết "traffic bình thường của ứng dụng này trông như thế nào". Kết hợp hai luồng thông tin → giảm false positive đáng kể.

---

### 1.4 Các Security Engine — "Vũ khí" trong kho

> 📖 **Nguồn**: [Security Practices](https://docs.openappsec.io/concepts/security-practices)

open-appsec không chỉ có ML. Đây là danh sách engine:

1. **Contextual ML Engine** (core, patented) — mô tả ở trên
2. **IPS (Intrusion Prevention System)** — signature-based cho 2800+ CVEs, hiển thị CVE number trong log
3. **Anti-Bot** (Premium) — 3 bước: inject script → thu thập keystroke/mouse/touch patterns → phán đoán human hay bot
4. **API Schema Enforcement** (Premium) — validate request theo OpenAPI/Swagger schema. Positive model (schema upload) hoặc negative model
5. **DLP (Data Loss Prevention)** — phát hiện data leak trong response
6. **File Security** — quét file upload
7. **Rate Limiting** — giới hạn số request theo URI trong time window
8. **Snort Rules** — import custom Snort signature

---

## PHẦN 2: CÀI ĐẶT THỰC CHIẾN

> 📖 **Nguồn**: [Install open-appsec for Linux](https://docs.openappsec.io/getting-started/start-with-linux/install-open-appsec-for-linux)

### 2.1 Linux + NGINX (Mode tự động — khuyến nghị)

**Yêu cầu**:
- OS được support (xem danh sách compatibility tại docs)
- NGINX/Kong/APISIX đã cài sẵn
- `/tmp` phải executable

```bash
# Bước 1: Tải installer
wget https://downloads.openappsec.io/open-appsec-install && chmod +x open-appsec-install

# Bước 2: Cài tự động (detect-learn mode mặc định)
./open-appsec-install --auto

# Tùy chọn có thể thêm:
# --token <token>    → kết nối SaaS WebUI
# --prevent          → bắt đầu ngay ở prevent-learn (không khuyến nghị)
```

Sau cài, file policy mặc định ở: `/etc/cp/conf/local_policy.yaml`

**Lưu ý quan trọng**: Installer có **Mode 1** (tự động) và **Mode 2** (thủ công). Mode 1 làm đúng những bước của Mode 2 — nên dùng Mode 1 trừ khi cần kiểm soát chi tiết.

### 2.2 Docker

```bash
# docker-compose.yml (ví dụ với NGINX Proxy Manager)
services:
  appsec-agent:
    image: ghcr.io/openappsec/agent:latest
    volumes:
      - ./open-appsec-advanced-model/open-appsec-advanced-model.tgz:/advanced-model/open-appsec-advanced-model.tgz:rw
```

### 2.3 Kubernetes

```bash
# Helm chart cài nguyên bộ NGINX Ingress + open-appsec
helm install open-appsec openappsec/open-appsec \
  --set appsec.agentToken=<token>
```

Hoặc dùng annotations trên Ingress resource để enable per-ingress.

### 2.4 Advanced ML Model — Bắt buộc cho production

> 📖 **Nguồn**: [Using the Advanced Machine Learning Model](https://docs.openappsec.io/getting-started/using-the-advanced-machine-learning-model)

**Basic Model** (mặc định trong GitHub) chỉ dùng cho test/monitor-only.
**Advanced Model** chính xác hơn, bắt buộc cho production.

```bash
# Linux: sau khi download tgz từ portal (my.openappsec.io)
tar -xvf open-appsec-advanced-model.tgz
cp <extracted>/* /etc/cp/conf/waap/

# Kiểm tra model đang dùng (từ v1.1.0)
open-appsec-ctl --status
# hoặc
open-appsec-ctl --version  # hiển thị ML model type + version
```

---

## PHẦN 3: CẤU HÌNH POLICY FILE

> 📖 **Nguồn**: [Local Policy File (Advanced)](https://docs.openappsec.io/getting-started/start-with-linux/local-policy-file-advanced)

### 3.1 Triết lý Object-Oriented của Policy File

Policy file YAML được thiết kế theo kiểu **object-oriented**: định nghĩa objects một lần, reference nhiều lần. Hiểu điều này giúp viết policy gọn và dễ maintain.

```yaml
# Cấu trúc tổng quan
policies:          # Policies (rules + mode)
practices:         # Security Practices (engine configs)
triggers:          # Log triggers
custom-responses:  # Block page tùy chỉnh
exceptions:        # Exceptions
trusted-sources:   # Trusted sources
source-identifiers: # Cách identify nguồn traffic
```

### 3.2 Policy — Xương sống cấu hình

```yaml
policies:
  default:                          # Rule mặc định cho tất cả
    triggers:
      - appsec-default-log-trigger
    mode: detect-learn              # detect-learn | prevent-learn | prevent
    practices:
      - webapp-default-practice
    custom-response: appsec-default-web-user-response

  specific-rules:                   # Override cho host/path cụ thể
    - host: "mail.example.com/webmail"
      mode: prevent-learn
      practices:
        - webapp-best-practice
      triggers:
        - appsec-special-log-trigger
```

**Ba chế độ hoạt động**:
- `detect-learn`: Chỉ log, không block. ML đang học. Dùng khi mới deploy.
- `prevent-learn`: Block và tiếp tục học. Chuyển sang đây sau khi ML đạt độ chín.
- `prevent`: Block, không cập nhật model nữa.

### 3.3 Practices — Cấu hình Engine

```yaml
practices:
  - name: webapp-best-practice
    web-attacks:
      override-mode: prevent        # Riêng engine này: prevent
      minimum-confidence: high      # critical | high | medium (default: high)
    ips:
      override-mode: prevent
      max-body-size-kb: 1000
    anti-bot:
      injected-endpoints:
        - every-request
```

**`minimum-confidence`** là tham số quan trọng:
- `medium`: Detect nhiều hơn, false positive cao hơn
- `high`: Cân bằng (default khuyến nghị)
- `critical`: Chỉ block khi rất chắc chắn, bỏ sót nhiều hơn

### 3.4 Trusted Sources — Tăng tốc learning

```yaml
trusted-sources:
  - name: internal-scanners
    num-of-sources: 3              # Số source để tin tưởng
    source-identifier: appsec-source-identifiers-sourceip-example

source-identifiers:
  - name: appsec-source-identifiers-sourceip-example
    identifiers:
      - source-identifier: sourceip
        value:
          - 10.0.0.0/8
          - 192.168.1.100
```

Trusted sources giúp ML engine hiểu traffic từ nguồn tin cậy (scanners nội bộ, monitoring tools) là benign, không ảnh hưởng model.

### 3.5 Exceptions — Bypass theo điều kiện

```yaml
exceptions:
  - name: appsec-exception-example
    actions:
      - action: skip                # skip (bypass) | accept | drop
        url: "/api/legacy-endpoint"
        sourceip:
          - 10.1.2.3
```

### 3.6 Apply Policy

```bash
# Sau mỗi lần chỉnh sửa policy file
open-appsec-ctl --apply-policy

# Xem policy hiện tại
open-appsec-ctl --show-policy

# Edit policy file trực tiếp
open-appsec-ctl --edit-policy
```

---

## PHẦN 4: VÒNG ĐỜI HỌC VÀ TUNING

> 📖 **Nguồn**: [Track Learning and Move From Learn/Detect to Prevent](https://docs.openappsec.io/how-to/configuration-and-learning/track-learning-and-move-from-learn-detect-to-prevent)

### 4.1 Các cấp độ Learning (Learning Levels)

open-appsec có các mốc học như bậc học phổ thông — cách trực quan để đánh giá độ chín của model:

```
Kindergarten → Primary School → Secondary School → University → ...
```

Từng cấp cần đủ:
- Số HTTP request đã inspect
- Thời gian đã học
- Số trusted sources
- Supervised learning suggestions

**Ví dụ thực tế**: "Kindergarten: cần thêm 999 requests và 6 giờ để lên Primary School"

### 4.2 Quy trình chuẩn: detect-learn → prevent

```
Bước 1: Deploy với mode detect-learn
         ↓
Bước 2: Xem log, review Tuning Suggestions trong Web UI
         ↓
Bước 3: Label suggestions: Malicious / Benign
  (Không bắt buộc nhưng giúp ML học nhanh hơn)
         ↓
Bước 4: Kiểm tra Learning Level đủ chín
         ↓
Bước 5: Chuyển sang prevent-learn
         ↓
Bước 6: Monitor false positives, xử lý exceptions
```

### 4.3 Best Practices Cấu Hình ML

> 📖 **Nguồn**: [How to Set Up open-appsec for Best Threat Prevention Results](https://www.openappsec.io/post/how-to-setup-open-appsec-for-best-threat-prevention-results-of-the-contextual-machine-learning-engin)

1. **Dùng Advanced Model** cho production (không dùng Basic Model)
2. **Cấu hình individual assets** cho từng ứng dụng — đừng dùng wildcard `https://*:*` cho tất cả nếu chúng có traffic pattern khác nhau. ML học per-asset.
3. **Cấu hình trusted sources** cho internal scanners, monitoring tools
4. **Thời gian learn đủ** trước khi chuyển sang prevent — không nóng vội
5. **Review Tuning Suggestions** để giúp model đạt độ chín nhanh hơn

---

## PHẦN 5: MONITORING VÀ LOGS

### 5.1 Xem Events (Linux standalone)

```bash
# Xem log events real-time
open-appsec-ctl --show-logs

# Filter theo severity
open-appsec-ctl --show-logs --level error
```

### 5.2 Log Triggers trong Policy

```yaml
log-triggers:
  - name: appsec-default-log-trigger
    access-control-log: true
    appsec-log:
      all-web-requests: false       # Log tất cả? (noisy, dùng để debug)
      detect-events: true
      prevent-events: true
    file:
      filename: /var/log/openappsec/appsec.log
    syslog-service:
      address: 192.168.1.10
      port: 514
```

---

## PHẦN 6: TÍCH HỢP PLATFORMS

### 6.1 NGINX (Linux embedded)

open-appsec-ctl tool dùng cho local management. File policy ở `/etc/cp/conf/local_policy.yaml`.

Attachment tương thích với các phiên bản NGINX cụ thể — kiểm tra danh sách tại: [NGINX attachment compatibility](https://docs.openappsec.io/getting-started/start-with-linux/install-open-appsec-for-linux)

### 6.2 Kong API Gateway

Hai cách tích hợp:
- **Traditional**: precompiled attachment (kiểm tra Kong compatibility list)
- **Lua plugin (Beta)**: `luarocks` install, không cần precompiled. Linh hoạt hơn.

### 6.3 Kubernetes (Helm)

```yaml
# values.yaml
appsec:
  agentToken: "<token-từ-portal>"
  mode: detect-learn
  
# Apply annotations trên Ingress
annotations:
  openappsec.io/practice: "webapp-best-practice"
  openappsec.io/mode: "prevent-learn"
```

### 6.4 Management: Local vs SaaS

| Feature | Local (YAML) | SaaS Web UI |
|---------|-------------|-------------|
| GitOps/IaC | ✅ Native | ❌ |
| Visual dashboard | ❌ | ✅ |
| Tuning Suggestions UI | ❌ | ✅ |
| Multi-deployment | Manual | ✅ Centralized |
| Advanced ML download | Portal | Auto included (Premium) |

---

## PHẦN 7: TROUBLESHOOTING CHECKLIST

### 7.1 Agent không start

```bash
# Kiểm tra status
open-appsec-ctl --status

# Xem logs agent
journalctl -u open-appsec -f

# Kiểm tra attachment có compatible không
ls /etc/cp/conf/
```

### 7.2 False Positives cao

1. Kiểm tra `minimum-confidence` trong practice — có thể đang ở `medium`
2. Xem Tuning Suggestions — label Benign cho traffic hợp lệ
3. Cấu hình `trusted-sources` cho internal tools
4. Thêm `exceptions` cho endpoint đặc biệt (legacy API, test tools)
5. Đảm bảo đang dùng **Advanced Model**, không phải Basic

### 7.3 ML chưa đủ chín trước khi prevent

Dấu hiệu: Learning Level vẫn ở thấp sau nhiều ngày → Kiểm tra:
- Có đủ traffic qua không?
- Trusted sources đã cấu hình chưa?
- Advanced model đã deploy chưa?

### 7.4 Policy không apply

```bash
# Validate syntax YAML trước
python3 -c "import yaml; yaml.safe_load(open('/etc/cp/conf/local_policy.yaml'))"

# Apply lại
open-appsec-ctl --apply-policy

# Xem version policy file (v1beta1 vs v1beta2)
head -5 /etc/cp/conf/local_policy.yaml
```

---

## PHẦN 8: KIẾN THỨC NÂNG CAO

### 8.1 API Security — Positive vs Negative Model

- **Negative model** (default): Block known-bad patterns
- **Positive model** (Premium): Upload OpenAPI schema → block anything not in schema

Positive model là bảo mật chặt chẽ nhất cho API — chỉ cho phép những gì đã define.

### 8.2 open-appsec vs WAF truyền thống — Điểm yếu cần biết

open-appsec **không phải silver bullet**:
- Cần thời gian learn trước khi chạy prevent (không "zero-config day-one prevent")
- Advanced Model phải download và cập nhật định kỳ (nhận email khi có update mới)
- Một số tính năng (Anti-Bot, API Schema) chỉ ở Premium edition
- Cần review Tuning Suggestions để đạt accuracy cao nhất

### 8.3 open-appsec trong môi trường chính phủ/enterprise

Điểm cần lưu ý khi deploy ở môi trường nhạy cảm:
- SaaS Management gửi log lên cloud — nếu air-gap, dùng local management thuần túy
- Advanced Model download cần kết nối portal — chuẩn bị cho offline deployment
- Community Edition (open source) vs Premium Edition — kiểm tra feature matrix

---

## HƯỚNG DẪN SỬ DỤNG SKILL NÀY

Khi người dùng hỏi về open-appsec:

1. **Câu hỏi khái niệm** → Giải thích từ analogies dễ hiểu, sau đó đi vào kỹ thuật
2. **Câu hỏi cài đặt** → Tham chiếu đúng phần, cung cấp command line cụ thể
3. **Câu hỏi troubleshoot** → Hỏi thêm context (version, platform, log output) trước khi kết luận
4. **So sánh với giải pháp khác** → Trung thực về trade-off, không oversell
5. **Câu hỏi về production** → Luôn nhấn mạnh Advanced Model + learning phase đủ chín

Khi không chắc về thông tin chi tiết (version-specific features, exact CLI flags) → hướng dẫn người dùng tra [docs.openappsec.io](https://docs.openappsec.io) thay vì đoán.

---

## THAM KHẢO NHANH — LINKS OFFICIAL

- **Docs chính**: https://docs.openappsec.io
- **GitHub**: https://github.com/openappsec/openappsec
- **Portal (Advanced Model download)**: https://my.openappsec.io
- **Technology deep-dive**: https://www.openappsec.io/tech
- **Install Linux**: https://docs.openappsec.io/getting-started/start-with-linux/install-open-appsec-for-linux
- **Policy File Advanced**: https://docs.openappsec.io/getting-started/start-with-linux/local-policy-file-advanced
- **Contextual ML**: https://docs.openappsec.io/concepts/contextual-machine-learning
- **Learning to Prevent**: https://docs.openappsec.io/how-to/configuration-and-learning/track-learning-and-move-from-learn-detect-to-prevent