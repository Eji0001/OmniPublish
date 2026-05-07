# OmniPublish — Security Architecture & Compliance Guide

**Version:** 2.0  |  **Classification:** Internal — Engineering  |  **Last Reviewed:** 2026-05

---

## 1. Architecture Overview

```
Internet
   │
   ▼
┌──────────────────────────────────────────────────────────┐
│  Cloudflare (WAF · DDoS · TLS termination · CDN)        │
└──────────────────────────────────────────────────────────┘
   │ HTTPS only
   ▼
┌──────────────────────────────────────────────────────────┐
│  Nginx Reverse Proxy                                     │
│  • HSTS preload      • Request size limits              │
│  • Rate limiting     • TLS 1.3 minimum                  │
└──────────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────────┐
│  Express API (Node 20)  — Security middleware stack:     │
│  Helmet → CORS → Body parser → HPP → Rate limiter       │
│  → Sanitiser → CSRF → Audit logger → Routes             │
└──────────────────────────────────────────────────────────┘
   │              │              │
   ▼              ▼              ▼
Supabase       Redis           Anthropic
(Postgres+RLS) (rate limits)   (AI API)
```

---

## 2. OWASP Top 10 Mitigation Matrix

| OWASP ID | Risk | Control |
|---|---|---|
| A01 Broken Access Control | HIGH | JWT auth on all routes · RLS in Postgres · User-ID scoping on all queries · Role-based middleware |
| A02 Cryptographic Failures | HIGH | AES-256-GCM for tokens at rest · TLS 1.3 in transit · bcrypt (12 rounds) for passwords · No MD5/SHA-1 |
| A03 Injection | HIGH | Parameterised queries via Supabase SDK · XSS sanitiser middleware · Zod schema validation · HPP guard |
| A04 Insecure Design | MEDIUM | Threat modelling per feature · Principle of least privilege · No debug data in prod responses |
| A05 Security Misconfiguration | HIGH | Helmet with strict CSP · Permissions-Policy · `x-powered-by` removed · No default credentials |
| A06 Vulnerable Components | MEDIUM | `npm audit` in CI/CD · Dependabot alerts · Monthly `npm audit --fix` · Node 20 LTS only |
| A07 Identification & Auth Failures | HIGH | Account lockout (5 attempts / 15 min) · JWT blacklist · Refresh token rotation · Timing-safe comparisons |
| A08 Software & Data Integrity | MEDIUM | Package lock files · Docker image digests · Signed commits enforced · Subresource Integrity on CDN assets |
| A09 Logging & Monitoring Failures | MEDIUM | Structured JSON logs · Daily rotating files · Audit trail in DB · Sentry for error alerting |
| A10 Server-Side Request Forgery | MEDIUM | Allowlist for external API URLs · No user-controlled redirect targets · Outbound firewall rules |

---

## 3. Authentication & Authorisation

### 3.1 Token Architecture

```
Client ────POST /auth/login────► API
                                  │ bcrypt.compare (constant time)
                                  │ Check lockout
                                  ▼
                             Issue JWT pair:
                             ┌─────────────────────────────┐
                             │ Access Token (15 min)       │
                             │  • HS256 signed             │
                             │  • sub, email, role, plan   │
                             │  • jti (unique ID)          │
                             │  • iss, aud claims          │
                             └─────────────────────────────┘
                             ┌─────────────────────────────┐
                             │ Refresh Token (7 days)      │
                             │  • HttpOnly Secure cookie   │
                             │  • SameSite=Strict          │
                             │  • path=/api/v1/auth        │
                             └─────────────────────────────┘
```

### 3.2 Refresh Token Rotation

1. Client sends refresh token (HttpOnly cookie)
2. Server validates signature + expiry
3. Old token's JTI is blacklisted immediately
4. New token pair is issued
5. Reuse of old token → **immediate session termination**

### 3.3 Account Lockout Policy

- 5 consecutive failed logins → 15-minute lockout
- Lockout stored in `users.locked_until` (DB-level, not memory)
- Auth responses are **timing-safe** to prevent user enumeration
- Failed attempts counter reset on successful login

### 3.4 Password Policy

| Requirement | Value |
|---|---|
| Minimum length | 12 characters |
| Uppercase required | Yes |
| Lowercase required | Yes |
| Number required | Yes |
| Special character required | Yes |
| Hashing algorithm | bcrypt, cost 12 |
| Reset token validity | 1 hour |
| Reset token storage | SHA-256 hash only (never plaintext) |

---

## 4. Data Protection

### 4.1 Encryption at Rest

**OAuth tokens (platform connections):**
- Algorithm: AES-256-GCM (authenticated encryption)
- Key: 32-byte key from `ENCRYPTION_KEY` env var
- Format stored: `iv:authTag:ciphertext` (all hex-encoded)
- Key rotation: monthly, via `scripts/rotate-encryption-key.js`

**Database:**
- Supabase managed Postgres with encryption at rest (AES-256)
- Backups encrypted with separate key
- No plaintext secrets in `metadata` JSONB columns

### 4.2 Encryption in Transit

- TLS 1.3 minimum (enforced at Cloudflare + Nginx)
- HSTS with 1-year max-age, `includeSubDomains`, `preload`
- Certificate pinning via Cloudflare

### 4.3 Row Level Security (RLS)

All user-data tables have RLS enabled. Policy: `auth.uid() = user_id`. The API service role bypasses RLS **only** for:
- Scheduled post processor
- Admin operations
- Audit log writes

---

## 5. API Security Controls

### 5.1 Rate Limiting Strategy

| Tier | Scope | Limit | Window |
|---|---|---|---|
| Global | All /api/ routes | 300 req | 15 min |
| Auth | /auth/login, /register | 15 req | 15 min |
| Auth slow-down | Auth routes | +500ms delay after 5 attempts | 15 min |
| AI adapt | /posts/adapt | 10–1000 req (plan-dependent) | 1 hour |
| Publish | /publish | 5–500 posts (plan-dependent) | 24 hours |
| Media upload | /media/upload | 50 files | 1 hour |

### 5.2 Input Validation Pipeline

```
Raw request body
      │
      ▼
HPP (HTTP Parameter Pollution guard)
      │
      ▼
requestSanitizer (recursive XSS + prototype pollution strip)
      │
      ▼
validateBody (Zod schema: types, lengths, enums, formats)
      │
      ▼
Route handler (trusted, typed data)
```

### 5.3 Content Security Policy

```
default-src 'self'
script-src  'self' 'strict-dynamic'
style-src   'self' 'unsafe-inline'
img-src     'self' data: blob: *.supabase.co *.cloudfront.net
connect-src 'self' https://api.anthropic.com https://*.supabase.co
object-src  'none'
frame-src   'none'
base-uri    'self'
form-action 'self'
upgrade-insecure-requests
```

---

## 6. Infrastructure Security

### 6.1 Container Security

- Base image: `node:20-alpine` (minimal attack surface)
- Non-root user (`app:app`) inside container
- `dumb-init` for proper signal handling
- No secrets in `Dockerfile` or image layers
- Image scanning: Trivy in CI/CD pipeline
- Docker content trust enabled

### 6.2 Secret Management

```
Local dev:   .env file (gitignored)
Production:  AWS Secrets Manager / Supabase vault
CI/CD:       GitHub Actions encrypted secrets
Rotation:    Monthly via automated scripts
```

### 6.3 Network Segmentation

```
Public Internet
      │ (HTTPS 443 only)
      ▼
Cloudflare WAF
      │
      ▼
Nginx (public subnet)
      │
      ▼
API containers (private subnet)
      │
      ├── Supabase (private peering)
      └── Redis    (private subnet, auth required)
```

---

## 7. Compliance

### 7.1 GDPR (EU Regulation 2016/679)

| Article | Requirement | Implementation |
|---|---|---|
| Art. 5 | Data minimisation | Only necessary fields collected. No tracking pixels. |
| Art. 17 | Right to erasure | `DELETE /api/v1/users/me` cascades via FK. Media purged from storage. |
| Art. 20 | Data portability | `GET /api/v1/users/me/export` returns full JSON export |
| Art. 25 | Privacy by design | RLS enforced at DB layer. Encryption at rest for tokens. |
| Art. 30 | Records of processing | Audit log in `audit_logs` table with retention policy |
| Art. 32 | Security measures | AES-256-GCM, TLS 1.3, bcrypt, JWT rotation |
| Art. 33 | Breach notification | Sentry alerting + incident response runbook |

### 7.2 SOC 2 Type II (Trust Service Criteria)

| Criteria | Control |
|---|---|
| CC6.1 Logical access | JWT auth · RBAC · MFA (planned) |
| CC6.2 Credentials | bcrypt hashed · no plaintext storage |
| CC6.7 Encryption | AES-256-GCM at rest · TLS 1.3 in transit |
| CC7.2 Monitoring | Winston structured logs · Sentry · audit trail |
| CC8.1 Change management | GitOps · PR reviews · automated tests |
| A1.1 Availability | Health probes · graceful shutdown · auto-restart |

### 7.3 CCPA (California Consumer Privacy Act)

- Privacy policy discloses all data categories collected
- `Do Not Sell` flag stored in `users.marketing_consent`
- Data export and deletion endpoints implemented
- Sub-processor list maintained in legal documentation

---

## 8. Incident Response

### Severity Levels

| Level | Description | SLA |
|---|---|---|
| P0 Critical | Auth bypass · mass data exposure | 1 hour response |
| P1 High | Rate limit bypass · token theft | 4 hour response |
| P2 Medium | XSS · CSRF · data leak (single user) | 24 hour response |
| P3 Low | Non-exploitable misconfiguration | Next sprint |

### Response Runbook (P0/P1)

1. **Detect** — Sentry alert / anomaly detection triggers
2. **Contain** — Rotate JWT secrets (invalidates all sessions) → deploy
3. **Assess** — Query `audit_logs` for scope of compromise
4. **Notify** — DPA notification within 72 hours (GDPR Art. 33)
5. **Remediate** — Patch, re-test, re-deploy
6. **Post-mortem** — Root cause analysis + control improvements

---

## 9. Security Checklist (Pre-Production)

- [ ] All environment variables set via secret manager (no .env in prod)
- [ ] `ENCRYPTION_KEY` is 32 unique random bytes — never reused
- [ ] JWT secrets are 64+ hex characters each
- [ ] HSTS preload submitted to hstspreload.org
- [ ] CSP policy tested with CSP Evaluator
- [ ] `npm audit` shows 0 high/critical vulnerabilities
- [ ] Postgres RLS tested — lateral movement between users impossible
- [ ] Rate limits verified under load test (k6)
- [ ] Sentry DSN configured and test error captured
- [ ] `/api/v1/health/ready` probe connected to load balancer
- [ ] Docker image scanned with Trivy — 0 critical CVEs
- [ ] GDPR deletion endpoint tested end-to-end
- [ ] Backup restoration tested in staging
- [ ] Incident response contacts documented and paged
