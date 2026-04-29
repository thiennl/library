# OPNsense VPN — Chi tiết

## WireGuard

### Road Warrior (Remote Access) Setup

**Server side (OPNsense):**
```
VPN → WireGuard → Local → Add
  Name: wg0
  Listen Port: 51820
  Tunnel Address: 10.10.0.1/24
  DNS: 192.168.1.1 (Unbound)
  Peers: [chọn sau khi tạo peers]
```

**Tạo peer cho mỗi client:**
```
VPN → WireGuard → Peers → Add
  Name: laptop_thien
  Public Key: <generate từ client>
  Tunnel Address: 10.10.0.2/32
  Allowed IPs: 10.10.0.2/32
  Endpoint: (để trống nếu client IP động)
```

**Generate key pair trên client:**
```bash
# Linux/macOS
wg genkey | tee private.key | wg pubkey > public.key
cat public.key  # copy vào OPNsense
```

**Firewall rules:**
```
# WAN: allow UDP 51820 inbound
Interface: WAN | Proto: UDP | Dst port: 51820 | Action: Pass

# WireGuard interface: allow từ VPN clients vào LAN
Interface: WireGuard | Src: 10.10.0.0/24 | Dst: 192.168.1.0/24 | Action: Pass
```

**Client config (wg0.conf):**
```ini
[Interface]
PrivateKey = <client private key>
Address = 10.10.0.2/32
DNS = 192.168.1.1

[Peer]
PublicKey = <OPNsense public key>
Endpoint = <WAN IP>:51820
AllowedIPs = 192.168.1.0/24  # Split tunnel — chỉ traffic LAN qua VPN
# AllowedIPs = 0.0.0.0/0    # Full tunnel — mọi traffic qua VPN
PersistentKeepalive = 25
```

## IPsec IKEv2 — Road Warrior (EAP-MSCHAPv2)

Phù hợp với Windows built-in VPN client, iOS, Android (không cần app thêm).

```
VPN → IPsec → Mobile Clients (tab)
  Enable: ✓
  User Authentication: Local Database
  Virtual Address Pool: 10.20.0.0/24
  DNS: 192.168.1.1

VPN → IPsec → Connections → Add
  Connection name: IKEv2-RoadWarrior
  IKE version: IKEv2
  Internet Protocol: IPv4
  Interface: WAN
  Remote Gateway: (để trống — any)
  Authentication method: EAP-MSCHAPv2
  My identifier: [WAN IP hoặc FQDN]
  Phase 1 Proposal:
    Encryption: AES-256-GCM
    Hash: SHA-256
    DH Group: 14 (2048 bit)
  Phase 2 Proposal:
    Protocol: ESP
    Encryption: AES-256-GCM
```

**Tạo user:**
```
System → Access → Users → Add
  Username: vpnuser1
  Password: [strong password]
  Group: VPN Users (tạo group trước)
```

📖 Ref: https://docs.opnsense.org/manual/vpn-ipsec-road-warrior.html

## IPsec Site-to-Site

```
VPN → IPsec → Connections → Add
  Description: Site-A to Site-B
  IKE version: IKEv2
  Interface: WAN
  Remote Gateway: 203.0.113.2  ← WAN IP của site B
  
  Authentication:
    Method: Mutual PSK
    Pre-Shared Key: [strong secret — same di cả 2 site]
    My identifier: 203.0.113.1
    Peer identifier: 203.0.113.2
  
  Phase 1 Proposal:
    Encryption: AES-256
    Hash: SHA-256
    DH Group: 14
    Lifetime: 28800
  
  Phase 2 (Child SA):
    Local Network: 192.168.1.0/24
    Remote Network: 10.0.0.0/24
    Protocol: ESP
    Encryption: AES-256
    Hash: SHA-256
    PFS Group: 14
```

**Quan trọng**: Ở site B cũng phải cấu hình ngược lại (swap Local/Remote).

📖 Ref: https://docs.opnsense.org/manual/vpn-ipsec-s2s.html

## OpenVPN — SSL/TLS Server

Phù hợp khi cần certificate-based auth hoặc qua firewall restrictive (dùng port 443/TCP).

**Bước 1: Tạo CA và certificates**
```
System → Trust → Authorities → Add (tạo CA)
System → Trust → Certificates → Add (tạo Server cert từ CA trên)
```

**Bước 2: Tạo OpenVPN server**
```
VPN → OpenVPN → Servers → Add
  Description: OpenVPN-RA
  Server Mode: Remote Access (SSL/TLS + User Auth)
  Protocol: UDP (hoặc TCP 443 nếu cần bypass firewall)
  Device mode: tun
  Interface: WAN
  Port: 1194
  TLS Authentication: ✓ (Generate)
  Peer Certificate Authority: [CA tạo ở bước 1]
  Server Certificate: [Server cert tạo ở bước 1]
  
  Tunnel Network: 10.8.0.0/24
  Local Network: 192.168.1.0/24
  
  Compression: Disabled (security reason)
  Auth Algorithm: SHA256
  Encryption Algorithm: AES-256-GCM
```

**Bước 3: Export client config**
```
System → Firmware → Plugins → os-openvpn-client-export (cài plugin)
VPN → OpenVPN → Client Export → Download Bundled
```

📖 Ref: https://docs.opnsense.org/manual/vpn-openvpn-server.html