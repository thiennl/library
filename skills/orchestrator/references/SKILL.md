---
name: orchestrator
description: >
  Điều phối và kết hợp nhiều skill chuyên biệt khi một task liên quan đến nhiều domain hạ tầng
  cùng lúc. Kích hoạt skill này khi câu hỏi kết hợp 2+ domain trong số: OPNsense firewall,
  CrowdSec IDS/IPS, open-appsec WAF, Zimbra mail server, Bun/TypeScript, Postfix, hoặc bất kỳ
  tổ hợp nào của các hệ thống hạ tầng này. Ví dụ trigger: "bảo vệ Zimbra với CrowdSec và OPNsense",
  "viết policyd bằng TypeScript cho Postfix", "hardening mail server toàn diện", "security stack
  cho hạ tầng email VNPT", "tích hợp WAF và IDS cho mail gateway", "CrowdSec bouncer OPNsense",
  "pipeline bảo mật nhiều lớp". Cũng dùng khi người dùng hỏi về kiến trúc tổng thể mà không
  chỉ rõ một tool cụ thể. Ưu tiên skill này hơn từng skill đơn lẻ khi phát hiện từ khóa của
  2+ domain xuất hiện trong cùng một câu hỏi.
---

# Infra Orchestrator

Skill điều phối đa domain — đọc và kết hợp các skill chuyên biệt để trả lời các câu hỏi
liên quan đến nhiều hệ thống hạ tầng cùng lúc.

## Bước 1 — Phân tích yêu cầu

Trước khi đọc bất kỳ skill nào, xác định:

1. **Có bao nhiêu domain** liên quan? Liệt kê ra.
2. **Mục tiêu cuối** là gì? (deploy, troubleshoot, thiết kế kiến trúc, viết code?)
3. **Integration point** là gì? Điểm nào các hệ thống cần "nói chuyện" với nhau?

Tham chiếu: `references/domain-map.md` — tra cứu skill path và cross-domain patterns.

## Bước 2 — Load skills theo thứ tự ưu tiên

**Quy tắc thứ tự đọc:**

```
Nếu task là THIẾT KẾ KIẾN TRÚC:
  → Đọc tất cả skill liên quan, theo thứ tự layer (perimeter → IDS → app → service)

Nếu task là TROUBLESHOOT:
  → Xác định layer nào đang lỗi, đọc skill của layer đó trước
  → Sau đó đọc skill của layer liền kề (upstream/downstream)

Nếu task là VIẾT CODE / SCRIPT:
  → Đọc skill ngôn ngữ (bun-typescript / port-to-bun) trước
  → Đọc skill domain để hiểu API/protocol cần implement

Nếu task là SECURITY HARDENING:
  → Thứ tự: opnsense → crowdsec → openappsec (từ ngoài vào trong)
```

Tham chiếu chi tiết: `references/multi-skill-execution.md`

## Bước 3 — Đọc skill files

Với mỗi skill cần dùng, thực hiện:
```
view /mnt/skills/<skill-path>/SKILL.md
```

Chỉ đọc reference files bên trong skill nếu task yêu cầu chi tiết sâu về domain đó.

## Bước 4 — Synthesis

Sau khi đọc xong các skill, soạn response theo cấu trúc trong `references/multi-skill-execution.md`:

- **Không** copy-paste từng skill riêng lẻ
- **Có** highlight integration points — đây là giá trị cốt lõi
- **Có** thứ tự triển khai thực tế (step-by-step tổng hợp)
- **Có** lưu ý conflict nếu các skill đề xuất approach mâu thuẫn

## Bước 5 — Đề xuất bổ sung (tùy chọn)

Nếu phát hiện domain quan trọng chưa có skill file, ghi chú cuối response:
> 💡 **Gợi ý:** Task này có thể benefit từ skill `<tên>` cho domain `<X>`. Tao có thể giúp tạo skill đó nếu mày muốn.

---

## Quick Reference — Cross-Domain Patterns

| Pattern | Skills cần load | Integration Point |
|---|---|---|
| Zimbra Security Stack | opnsense + crowdsec + openappsec | OPNsense alias ← CrowdSec LAPI; nginx → open-appsec |
| Mail Policy Daemon | bun-typescript + port-to-bun | Postfix smtpd_restriction → unix socket |
| Firewall + IDS | opnsense + crowdsec | CrowdSec bouncer → OPNsense firewall table |
| WAF Comparison | openappsec + crowdsec | Deployment mode, log integration |
| Script Migration + Dev | port-to-bun + bun-typescript | Bun Shell API, type safety layer |

---

## Nguyên tắc cốt lõi

1. **Đọc skill trước, trả lời sau** — không bao giờ skip bước đọc SKILL.md
2. **Layer model** — luôn tư duy theo tầng hạ tầng, không xáo trộn domain
3. **Integration > Juxtaposition** — giá trị là ở điểm kết nối, không phải ghép nội dung
4. **Thành thật về giới hạn** — nếu skill không tồn tại, nói rõ thay vì bịa