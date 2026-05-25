# 🔐 HealthSecure — Identity & Security Intelligence Platform

HealthSecure is a full‑stack identity security platform designed to demonstrate modern authentication, MFA, device intelligence, risk scoring, and security event monitoring.  
Built with **Python, Flask, AWS CloudWatch, CI/CD, and modern security engineering practices**, this project showcases real‑world IAM and AppSec capabilities.

---

## 🚀 Live Demo
**https://healthsecure.us**

---

## 🧩 Features

### 🔑 Authentication & Identity
- Username/password login  
- Azure AD login  
- Auth0 login  
- MFA (TOTP)  
- Trusted device recognition  
- Device fingerprinting  
- Session tracking with UUIDs  
- Role‑based access (Admin/User)

### 🛡 Security Intelligence
- Risk‑based authentication  
- Login anomaly detection  
- IP + geolocation intelligence  
- Device type + OS + browser detection  
- Suspicious login alerts  
- CloudWatch security event pipeline  
- Admin security dashboard  
- Login timeline & audit logs  

### 📊 Admin Dashboard
- User management  
- Security events viewer  
- Device history  
- MFA status  
- Risk scoring  
- Last login details  
- IP + location mapping  

### ☁ Cloud & Infrastructure
- AWS CloudWatch Logs integration  
- AWS IAM roles for secure event ingestion  
- Render cloud hosting (IaaS)  
- GitHub Actions CI/CD  
- Automated security scanning (pip‑audit, Gitleaks)  
- YAML‑based pipeline definitions  

---

## 🏗 Architecture Overview

User → Flask App → Auth Layer → MFA → Device Intelligence
↓
Security Events → AWS CloudWatch → (Future: Lambda → DynamoDB)
↓
Admin Dashboard → Risk Analytics → Audit Logs

Code

---

## 🛠 Tech Stack

**Backend:** Python, Flask  
**Frontend:** HTML, CSS, JS  
**Security:** MFA, hashing, device fingerprinting, risk scoring  
**Cloud:** AWS CloudWatch, IAM  
**CI/CD:** GitHub Actions (YAML)  
**Hosting:** Render (IaaS)  
**Database:** SQLite (local), Render PostgreSQL (optional)  

---

## 🔍 CI/CD & Security Automation

### ✔ Dependency vulnerability scanning  
### ✔ Secret scanning (Gitleaks)  
### ✔ Automated build & deploy  
### ✔ YAML‑based GitHub Actions  
### ✔ Pipeline hardening  
### ✔ Artifact uploads (SARIF, JSON)  

---

## 📸 Screenshots (Add your images here)

- Login page  
- MFA setup  
- Admin dashboard  
- Security events  
- Risk scoring  
- Profile page  

---

## 🧪 How to Run Locally

```bash
git clone https://github.com/<your-username>/healthsecure
cd healthsecure
pip install -r requirements.txt
python app.py
Create a .env file with:

Code
ADMIN_USERNAME=yourname
ADMIN_PASSWORD=yourpassword
AUTH0_CLIENT_ID=xxx
AUTH0_CLIENT_SECRET=xxx
AWS_REGION=us-east-1
