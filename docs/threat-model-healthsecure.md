# HealthSecure Threat Model (STRIDE)

## 1. Assets

- User accounts and credentials
- Access tokens (JWTs)
- Refresh tokens (if enabled)
- Session cookies
- Device fingerprints
- Trusted device records
- Location data (GPS, IP-based)
- Admin accounts and admin sessions
- Security event logs (login events, device/location data)

## 2. Entry Points

- /login (username/password)
- /auth/auth0/* (Auth0 login + callback)
- /auth/azure/* (Azure AD login + callback)
- /logout
- /admin/* (admin dashboard, security views)
- Any API endpoints used by frontend (if applicable)

## 3. STRIDE Analysis by Component

### 3.1 Authentication Flows (Auth0, Azure AD, Custom Login)

- **Spoofing**
  - Risk: Stolen credentials, token replay, fake identity.
  - Mitigations: OAuth2/OIDC with PKCE, HTTPS-only, JWT validation, secure cookies, session timeout.

- **Tampering**
  - Risk: Manipulated redirect_uri, modified tokens, altered parameters.
  - Mitigations: Strict redirect URI allowlist, state parameter, signature validation, server-side checks.

- **Repudiation**
  - Risk: User denies performing a login or action.
  - Mitigations: Login logs with timestamp, IP, device fingerprint, and location.

- **Information Disclosure**
  - Risk: Tokens or session IDs leaked, sensitive data exposed.
  - Mitigations: HttpOnly cookies, SameSite, no tokens in URL, HTTPS-only, minimal data in logs.

- **Denial of Service**
  - Risk: Brute force, credential stuffing, login endpoint flooding.
  - Mitigations: Rate limiting, throttling, IP-based blocking, firewall logic.

- **Elevation of Privilege**
  - Risk: Normal user gaining admin access.
  - Mitigations: Role checks on server side, admin-only routes, separate admin session checks.

### 3.2 Device & Location Intelligence

- **Spoofing**
  - Risk: Fake device fingerprint, fake GPS/location.
  - Mitigations: Combine multiple signals (IP, device, behavior), mark high-risk sessions, admin review.

- **Tampering**
  - Risk: Manipulated location data or client-side values.
  - Mitigations: Server-side validation, IP-based geo checks, anomaly detection.

- **Information Disclosure**
  - Risk: Overexposure of device/location data.
  - Mitigations: Limit what is shown, admin-only visibility, no raw GPS coordinates to normal users.

### 3.3 Admin Dashboard

- **Spoofing**
  - Risk: Unauthorized user accessing admin dashboard.
  - Mitigations: Admin authentication, RBAC, secure sessions.

- **Information Disclosure**
  - Risk: Exposure of logs, devices, locations, and user data.
  - Mitigations: Admin-only access, HTTPS, minimal PII in logs.

- **Tampering / Elevation of Privilege**
  - Risk: Admin actions misused or modified.
  - Mitigations: Server-side authorization checks, audit logging of admin actions (planned).

## 4. High-Risk Areas

- Authentication callbacks (Auth0, Azure AD)
- Session management and cookies
- Admin dashboard access
- Storage and handling of device and location data

## 5. Planned Improvements

- Integrate SIEM for centralized log analysis.
- Add formal incident response workflows and playbooks.
- Add AWS-based logging/monitoring component.
- Expand anomaly detection rules and alerting.
