# Domain Map — Skill Registry

## IT Infrastructure & Security Skills

| Skill Path | Domain | Trigger Keywords |
|---|---|---|
| `user/opnsense` | Firewall / Network | OPNsense, pfSense, firewall rules, NAT, VLAN, VPN, HAProxy, Suricata, CARP, Unbound |
| `user/crowdsec` | IDS/IPS / Threat Intel | CrowdSec, bouncer, LAPI, CAPI, scenario, parser, blocklist, community blocklist |
| `user/openappsec` | WAF / AppSec | open-appsec, WAF ML, appsec-ctl, OWASP, API schema enforcement, anti-bot |
| `user/zimbra`* | Mail Server | Zimbra, ZCS, mailbox, zimlet, LDAP auth, preauth, postfix, amavis |

> *Nếu zimbra chưa tồn tại, dùng kiến thức nền + đọc context từ conversation history.

## Programming & Dev Skills

| Skill Path | Domain | Trigger Keywords |
|---|---|---|
| `user/bun-typescript-mentor` | TypeScript / Bun runtime | Bun, TypeScript, tsx, tsconfig, Hono, Elysia, Prisma, type system |
| `user/port-to-bun-typescript` | Code Migration | port, rewrite, convert Perl/Python/Bash → Bun/TypeScript |
| `user/mojo-mentor` | Mojo lang | Mojo 🔥, fn vs def, SIMD, GPU programming, Modular |

## Notion Workflow Skills

| Skill Path | Domain | Trigger Keywords |
|---|---|---|
| `user/notion-knowledge-capture` | Notion Docs | lưu vào Notion, capture knowledge, tạo page Notion |
| `user/notion-meeting-intelligence` | Notion Meetings | chuẩn bị họp, meeting agenda, pre-read Notion |
| `user/notion-research-documentation` | Notion Research | research Notion, tổng hợp Notion, báo cáo Notion |
| `user/notion-spec-to-implementation` | Notion Tasks | spec → task, implementation plan, breakdown Notion |

## Cross-Domain Combinations (Multi-Skill Patterns)

### Security Stack cho Zimbra
- **Skills cần load:** `opnsense-mentor` + `crowdsec-mentor` + `openappsec-mentor`
- **Trigger:** "bảo vệ Zimbra bằng WAF/firewall", "security stack mail server", "hardening Zimbra"
- **Thứ tự đọc:** opnsense (perimeter) → crowdsec (IDS layer) → openappsec (app layer)

### Postfix Policy Daemon / Mail Pipeline
- **Skills cần load:** *(Zimbra context)* + `bun-typescript-mentor` hoặc `port-to-bun-typescript`
- **Trigger:** "viết policyd bằng TypeScript", "rewrite policy daemon", "Postfix milter Bun"

### Firewall + IDS Integration
- **Skills cần load:** `opnsense-mentor` + `crowdsec-mentor`
- **Trigger:** "CrowdSec bouncer OPNsense", "tích hợp IPS vào firewall", "block IP tự động OPNsense"

### WAF Evaluation / Comparison
- **Skills cần load:** `openappsec-mentor` + `crowdsec-mentor`
- **Trigger:** "so sánh WAF", "chọn WAF cho Zimbra", "open-appsec vs CrowdSec AppSec"

### Code Migration + Testing
- **Skills cần load:** `port-to-bun-typescript` + `bun-typescript-mentor`
- **Trigger:** "chuyển script Python sang Bun rồi viết thêm unit test"