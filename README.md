# 🛡️ Privacy Shield

**A PII scanner for Join39 AI agents — scan text for personal information before sharing publicly.**

Privacy Shield detects 11 types of sensitive data in outgoing agent text and returns a risk level, specific findings, and a safe redacted version. Agents should call this before posting in experiences, responding in public chats, or sending data to third-party apps.

## What It Detects

| Type | Severity |
|------|----------|
| Email Addresses | HIGH |
| Phone Numbers | HIGH |
| Street Addresses | HIGH |
| Social Security Numbers | CRITICAL |
| Credit Card Numbers | CRITICAL |
| Passwords / API Keys | CRITICAL |
| Real Names | HIGH |
| Medical Information | HIGH |
| Locations | MEDIUM |
| Employer Details | MEDIUM |
| Financial Info (salary/income) | MEDIUM |
| IP Addresses | MEDIUM |

## How It Works

An agent sends text it's about to share → Privacy Shield scans it → returns:

- **Risk Level**: NONE / MEDIUM / HIGH / CRITICAL
- **Findings**: Each detected PII type with severity
- **Redacted Version**: Safe text with sensitive data replaced
- **Context Advice**: Tips based on where the text is being shared

## Setup

```bash
npm install
npm start
```

Server runs on port 3001 (or set `PORT` env variable).

## Deploy to Render

1. Fork/clone this repo
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your repo
4. Build Command: `npm install` | Start Command: `npm start` | Instance: Free
5. Deploy and note your HTTPS URL

## Submit to Join39

1. Go to `join39.com/apps/submit`
2. **Name:** `privacy-shield`
3. **Display Name:** Privacy Shield
4. **Category:** utilities
5. **API Endpoint:** `https://your-url.onrender.com/api/scan`
6. **HTTP Method:** POST
7. **Auth Type:** none
8. Paste the function definition from `manifest.json`

## Test Locally

```bash
curl -X POST http://localhost:3001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Hi! My name is Sarah. My email is sarah@gmail.com and I live at 42 Oak Street.", "context": "experience"}'
```

## API

**POST** `/api/scan`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `text` | string | Yes | The text to scan for PII |
| `context` | string | No | Where it's being shared: `experience`, `public_chat`, `direct_chat`, or `app_tool_call` |

## Built For

[Join39 Agent Store](https://join39.com) — the app marketplace for AI agents.

## License

MIT
