# MailBridge API — Multi-Tenant Gmail SMTP Infrastructure

MailBridge API is a production-ready, multi-tenant email delivery platform and developer API backed by Firebase, Redis/BullMQ, Razorpay, and encrypted Gmail/Workspace SMTP pools.

---

## Key Features

- **ZetPay-Inspired Dashboard & Dark Developer Docs**: Clean, responsive frontend with SVG usage charts, deliverability statistics, and interactive developer documentation.
- **Firebase Authentication & Secure Sessions**: Email/password authentication, custom claims (`admin: true`), HttpOnly/Secure/SameSite session cookies, and double-submit CSRF protection.
- **Developer API Key Management**: Tenant-scoped, SHA-256 hashed API keys with instant revocation and quota enforcement.
- **Credit Reservation Engine**: Concurrency-safe Firebase wallet transactions. Exactly one credit is reserved prior to dispatch, consumed upon provider acceptance, and released on pre-send failures.
- **Multi-Account Gmail SMTP Pool**: Encrypted credentials (AES-256-GCM), daily per-sender quota tracking, SMTP verification, and pinned tenant assignments.
- **BullMQ / Redis Asynchronous Processing**: Robust job queues, stuck-job detection, dead-letter queue (DLQ), and automated queue recovery.
- **Complete Razorpay Payment & Refund Lifecycle**: Order creation, checkout signature verification, captured payment webhooks, full/partial refund processing, and dispute/chargeback management.
- **Financial Reconciliation & Ledger Auditing**: Multi-ledger verification across orders, payments, refunds, disputes, and wallet ledgers with audit logs and CLI verification.
- **Bounce & Complaint Suppression**: Synchronous SMTP 5xx hard bounce auto-suppression, repeated soft-bounce thresholding, and spam complaint handling.
- **Configurable Data Retention & GDPR Deletion**: Configurable retention policies for logs, message content, and tickets, with GDPR right-to-be-forgotten user data purging and financial record pseudonymization.
- **Distributed Rate Limiting**: Multi-scope rate limiter backed by atomic Redis Lua scripts with sliding-window memory fallback.
- **16 Fully Functional Admin Management Pages**: Real backend APIs for Dashboard, Users, Senders, Email Monitoring, Logs, Keys, Credits, Payments, Refunds, Disputes, Reconciliation, Queue, Abuse, Tickets, Settings, and Admin Activity Logs.

---

## Architecture & Technology Stack

| Layer | Technologies |
|---|---|
| **Backend** | Node.js 20+, Express 4.21, Helmet 8.0, CORS |
| **Authentication** | Firebase Authentication, Firebase Admin SDK 13.0 |
| **Datastore** | Firebase Realtime Database (with strict server-only security rules) |
| **Job Queue & Cache** | Redis 7+, BullMQ 6.5, IORedis 6.0 |
| **Email Dispatch** | Nodemailer 10.3, Gmail SMTP / Google Workspace OAuth2 |
| **Billing** | Razorpay Node SDK / REST API with HMAC-SHA256 signature verification |
| **Security** | AES-256-GCM authenticated encryption, SHA-256 key hashing, CSRF tokens |
| **Testing** | Node.js Native Test Runner (`node --test`), Supertest |

---

## Quick Start (Development)

### 1. Prerequisites
- Node.js 20+
- Redis (optional for test suites, required for live sending worker)
- Firebase Project with Realtime Database and Authentication enabled

### 2. Installation
```bash
git clone <repo-url>
cd mailbridge
npm ci
```

### 3. Environment Configuration
Copy `.env.example` to `.env` and fill in your values:
```bash
cp .env.example .env
```
Key environment variables:
- `FIREBASE_PROJECT_ID`, `FIREBASE_DATABASE_URL`, `FIREBASE_WEB_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`
- `REDIS_URL`
- `SENDER_ENCRYPTION_KEY` (`openssl rand -base64 32`)
- `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`

### 4. Database Setup & Migration
Seed platform settings and retention rules:
```bash
npm run db:migrate
```

### 5. Running the Application
```bash
npm start
```
The server will start on `http://localhost:3000`.

---

## Automated Tests

Run the complete 66-test suite:
```bash
npm test
```

All 66 tests execute in isolated environments with 100% pass rate:
- `backend/test/refunds.test.js`: Full & partial refunds, duplicate webhooks, credit recovery.
- `backend/test/disputes.test.js`: Dispute handling, credit hold, won restoration, admin resolution.
- `backend/test/reconciliation.test.js`: Multi-ledger reconciliation, missing credit detection.
- `backend/test/recovery.test.js`: Stuck job detection, auto-recovery to unknown, DLQ release.
- `backend/test/bounces.test.js`: Hard bounce auto-suppression, soft-bounce threshold, complaints.
- `backend/test/retention.test.js`: Data retention cleanup, GDPR user deletion with pseudonymization.
- `backend/test/ratelimit.test.js`: Distributed rate limits across users, IPs, keys, and payments.
- `backend/test/security.test.js`: IDOR protection, API key hashing, CSRF tokens, admin verification.
- `backend/test/e2e.test.js`: Complete 18-step end-to-end integration test.
- `backend/test/management.test.js`: Admin management APIs and status enforcement.
- `backend/test/payments.test.js`: Razorpay orders, captured payments, and webhook security.

---

## Database & CLI Commands

| Command | Description |
|---|---|
| `npm test` | Runs the automated test suite |
| `npm run db:migrate` | Seeds platform settings, retention rules, and rate limits |
| `npm run db:backup` | Exports an atomic JSON database backup |
| `npm run db:restore -- --file=<path>` | Restores a database snapshot |
| `npm run integrity:check` | Verifies mathematical financial ledger integrity across all wallets |
| `npm run purge:logs` | Cleans expired email logs, closed tickets, and old content |

---

## Production Deployment

Refer to [`DEPLOYMENT.md`](DEPLOYMENT.md) for detailed instructions on deploying to Railway, Hostinger, Cloudflare, configuring Firebase security rules, and setting up Razorpay webhooks.
