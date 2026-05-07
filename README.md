# W55RP20 HTTPS Server with Authentication

### 계정 생성 화면
<img width="446" height="408" alt="image" src="https://github.com/user-attachments/assets/141f1c5b-37d5-401d-9260-aef4a5d3e0ac" />

### 로그인 화면
<img width="841" height="423" alt="image" src="https://github.com/user-attachments/assets/d0c17db3-1d8d-4aee-b7e7-0e5264d43f57" />

---

## Warning

This project is currently under development.

Normal operation is not guaranteed, and some functions may be unstable or incomplete.

---

## Overview

This repository implements an embedded **HTTPS server with login authentication** on the W55RP20 (RP2040 + W5500).

- HTTPS server on port `443` (TLS 1.2, mbedTLS)
- Login system with SHA-256 hashed password storage in Flash
- Session cookie-based authentication (30-minute timeout)
- Up to 5 user accounts
- SNMP v1 Agent on UDP port `161`

---

## Authentication Flow

```
First Access (no accounts)
  → /setup  : Enter creation password → Create account

Account exists
  → /login  : ID / Password login → Session cookie issued
  → /       : Main page (authenticated)
  → /account: Add / Delete accounts
  → /logout : Invalidate session
```

### Account Creation Password

> `wiznet_w55rp20`

This password is required to create new user accounts. It is stored as a SHA-256 hash in the firmware and cannot be changed via the web interface.

---

## How It Works

1. Device boots and initializes the network stack
2. DHCP assigns an IP address
3. HTTPS server opens port `443`, SNMP Agent opens UDP `161`
4. Browser connects over HTTPS → TLS handshake
5. Login page is served — authentication required before accessing main page
6. Session token issued as a secure cookie after successful login

---

## Security

| Layer | Method |
|---|---|
| Transport | TLS 1.2 (`TLS-RSA-WITH-AES-256-GCM-SHA384`) |
| Session | Random 16-byte token, HttpOnly + Secure cookie |
| Password storage | SHA-256 hash in Flash (plaintext never stored) |
| Account creation | Separate creation password required |

### TLS Session Caching

mbedTLS session caching is enabled to reduce reconnection handshake time.

- First connection: full TLS handshake (~2–4 seconds, RSA bottleneck on RP2040)
- Reconnection: session resumed (tens of milliseconds)

### Planned Improvement

- Replace RSA-2048 certificate with **ECDSA P-256**
- Expected handshake reduction: ~2.25s → ~100–200ms per connection
- Security level improves: 112 bit → 128 bit

---

## System Architecture

```
Browser
  └── HTTPS (TCP 443) ──▶ TLS handshake (mbedTLS)
                               └── Auth check (httpsAuth)
                                       └── Main page / Login / Account mgmt

SNMP Manager
  └── UDP 161 ──▶ SNMP Agent (ioLibrary)
                      └── System MIB response
```

**Key source files:**

| File | Role |
|---|---|
| `port/app/platform_handler/src/httpHandler.c` | HTTPS server task, URL routing |
| `port/app/platform_handler/src/httpsAuth.c` | Account / session management |
| `port/app/mbedtls/src/SSLInterface.c` | TLS context, session cache |
| `port/app/platform_handler/src/snmpHandler.c` | SNMP Agent task |
| `libraries/ioLibrary_Driver/Internet/SNMP/snmp_custom.c` | SNMP OID table |

---

## Socket Allocation (W5500)

| Socket | Purpose |
|---|---|
| 0 | Data |
| 1 | Config UDP |
| 2 | Config TCP |
| 3 | DHCP / DNS |
| 4 | HTTPS server 1 |
| 5 | HTTPS server 2 |
| 6 | HTTPS server 3 |
| 7 | SNMP Agent UDP 161 |

---

## ioLibrary Patch

SNMP-related fixes to the upstream ioLibrary are maintained as a patch file.

```bash
cd libraries/ioLibrary_Driver
git checkout b981401
git apply ../../ioLibrary_snmp_patch.patch
```

See [ioLibrary_snmp_patch_HOW_TO_APPLY.md](ioLibrary_snmp_patch_HOW_TO_APPLY.md) for details.

---

## Certificate Notes

This project uses a self-signed development certificate.

- A browser security warning will appear on first access — this is expected
- For internal testing, the warning can be safely ignored
- Future plan: replace with ECDSA P-256 self-signed certificate

---

## Future Plans

- [ ] ECDSA P-256 certificate to replace RSA-2048 (handshake speed + security)
- [ ] HTTPS page to display real-time sensor data (UART input)
- [ ] SNMP OID extension for sensor channels
- [ ] SNMP Trap support (Phase 2)
