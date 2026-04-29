# Multi-Skill Execution Guide

## Nguyên tắc khi kết hợp nhiều skill

### 1. Phân tầng theo kiến trúc (Layer Model)
Khi task liên quan đến hạ tầng bảo mật, đọc skill theo thứ tự từ ngoài vào trong:

```
[Perimeter]     opnsense-mentor       → Firewall, NAT, routing
    ↓
[IDS/Threat]    crowdsec-mentor       → Phát hiện, blocklist
    ↓
[App Layer]     openappsec-mentor     → WAF, OWASP protection
    ↓
[Application]   (zimbra / mail context)
```

### 2. Đọc skill nào trước?
- **Nếu câu hỏi về connectivity/routing** → opnsense trước
- **Nếu câu hỏi về attack detection/response** → crowdsec trước
- **Nếu câu hỏi về HTTP/web application** → openappsec trước
- **Nếu câu hỏi về code implementation** → bun-typescript hoặc port-to-bun trước

### 3. Synthesis — Cách tổng hợp output đa skill

Sau khi đọc các skill liên quan, trình bày theo cấu trúc:

```
## Tổng quan kiến trúc
[Sơ đồ/mô tả luồng kết hợp các component]

## [Skill A] — [Tên domain]
[Hướng dẫn từ skill A]

## [Skill B] — [Tên domain]
[Hướng dẫn từ skill B, có tham chiếu đến cấu hình của A nếu cần]

## Integration Points
[Những điểm kết nối giữa các component — đây là giá trị cốt lõi của orchestration]

## Thứ tự triển khai
[Step-by-step tổng hợp]
```

### 4. Conflict Resolution
Nếu hai skill đưa ra hướng dẫn mâu thuẫn (ví dụ: cả CrowdSec và open-appsec đều muốn xử lý block ở layer 7):
- Phân tích trade-off rõ ràng
- Đề xuất phân công trách nhiệm (separation of concerns)
- Không bịa đặt "đây là best practice" nếu không có tài liệu rõ

### 5. Khi skill chưa tồn tại
Nếu domain cần thiết nhưng chưa có skill file:
1. Thông báo rõ: "Chưa có skill cho domain X, đang dùng kiến thức nền"
2. Đề xuất tạo skill mới sau khi hoàn thành task
3. Không pretend đang đọc skill file nếu không tồn tại

## Ví dụ phân tích yêu cầu

**Input:** "Cấu hình để CrowdSec bouncer hoạt động với OPNsense, block IP tấn công Zimbra"

**Phân tích:**
- Domain 1: OPNsense (firewall enforcement) → đọc `opnsense-mentor`
- Domain 2: CrowdSec (detection + decision) → đọc `crowdsec-mentor`
- Domain 3: Zimbra (protected target, log source) → context từ conversation
- Integration point: CrowdSec LAPI → OPNsense firewall alias

**Thứ tự đọc:** crowdsec-mentor (architecture) → opnsense-mentor (enforcement config)