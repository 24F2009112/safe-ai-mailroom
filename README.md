# Safe AI Mailroom Agent

A deployable HTTPS API for the “Safe AI Mailroom” task. It extracts mail/approval facts, checks authority **before** proposing a consequential action, cites source-verifiable evidence, logs decisions, and refuses to record completion until a matching signed receipt is cryptographically verified.

## What it does

- `POST /v1/mailroom/actions`: evaluates one case and returns exactly one selected action plus evidence and an authority report.
- `GET /health`: checks service and audit-store availability.
- `GET /.well-known/agent.json` and `GET /.well-known/agent-card.json`: public Agent Card metadata.
- `GET /v1/mailroom/actions/{action_id}`: retrieves the stored decision.
- Uses an OpenAI-compatible API for natural-language extraction when `OPENAI_API_KEY` is configured. Normal code—not the model—does the final authorization, scope checks, hashing, database writes, and receipt signature verification.
- Without an AI key, it uses a conservative fallback parser. It may hold more cases for review; that is safer than guessing.
- It **does not send/forward/release email or documents**. It returns a decision/proposal for the external system to execute. It never marks a consequential action complete without a valid signed receipt.

## Request contract

Send a JSON object. The service accepts either structured fields or natural-language case content. Example:

```json
{
  "case_id": "case-104",
  "email": {
    "from": "manager@example.com",
    "to": "maya@example.com",
    "requested_action": "forward",
    "document": "Q3-report.pdf",
    "body": "Please forward Q3-report.pdf to maya@example.com."
  },
  "approval": {
    "signed": true,
    "status": "current",
    "action": "forward",
    "recipient": "maya@example.com",
    "document": "Q3-report.pdf"
  },
  "permitted_actions": ["forward", "hold_for_review", "request_clarification"]
}
```

The names `message`, `mail`, `inbound_email`, `case_file`, `authority`, `authorization`, `approval_document`, `allowed_actions`, `available_actions`, and `action_options` are also accepted in common locations. If the caller provides action options, the agent selects from that menu when possible. If it contains no safe fallback and the requested action is not authorized, the response explicitly says no external action is authorized.

Response key fields:

- `action_id`: stable identifier for the proposed action.
- `action` / `selected_action`: single selected action.
- `authority_check.authorized`: true only when the signature is established, approval status is current, and the action, recipient, and document scopes match.
- `evidence`: verbatim quotes validated against the submitted case payload; an unverified model quote is discarded.
- `receipt.verified` and `completed`: false until a signed receipt has a valid signature and matches `case_id`, `action_id`, action, and recipient.

## Receipt signatures

A Boolean such as `"verified": true` is not trusted. Configure **one** mechanism that matches the receipt issuer:

### HMAC-SHA256

Set `RECEIPT_HMAC_SECRET` to a shared secret in the deployment's secret/environment settings. The receipt issuer must HMAC-sign UTF-8 compact canonical JSON (`sort_keys=True`, separators `(',', ':')`) containing all receipt fields **except** `signature`, `signature_algorithm`, `algorithm`, and `verified`. For example, the signed body may be:

```json
{
  "case_id": "case-104",
  "action_id": "act_<id returned by the agent>",
  "action": "forward",
  "recipient": "maya@example.com",
  "issued_at": "2026-10-24T10:00:00Z",
  "signature_algorithm": "hmac-sha256",
  "signature": "<lowercase hex HMAC-SHA256>"
}
```

The HMAC is calculated over the compact JSON with `signature` and `signature_algorithm` removed. The above sample's `signature` is a placeholder, not a usable receipt. The agent requires the exact `case_id`, `action_id`, action and recipient to match the proposed action.

### Ed25519

Alternatively configure `RECEIPT_PUBLIC_KEY` with the receipt issuer's PEM-encoded Ed25519 **public** key and set `signature_algorithm` to `ed25519`. The receipt issuer signs the same canonical unsigned JSON. Never put a private key in this service.

If the task platform provides a proprietary receipt signature scheme, adapt `verify_receipt_signature()` to that documented scheme rather than bypassing verification.

## Run locally (Windows PowerShell)

Install Python 3.11 or 3.12, then:

```powershell
cd safe-ai-mailroom
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set environment variables for the current PowerShell session (or configure them in your IDE):

```powershell
$env:OPENAI_API_KEY = "YOUR_API_KEY"
$env:OPENAI_MODEL = "gpt-4o-mini"
$env:DATABASE_PATH = ".\mailroom_audit.sqlite3"
```

Then run:

```powershell
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Test the health and card endpoints in a second PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/.well-known/agent.json
```

Test a case:

```powershell
$body = @{
  case_id = "case-104"
  email = @{
    from = "manager@example.com"
    to = "maya@example.com"
    requested_action = "forward"
    document = "Q3-report.pdf"
    body = "Please forward Q3-report.pdf to maya@example.com."
  }
  approval = @{
    signed = $true
    status = "current"
    action = "forward"
    recipient = "maya@example.com"
    document = "Q3-report.pdf"
  }
  permitted_actions = @("forward", "hold_for_review", "request_clarification")
} | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/mailroom/actions -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 12
```

This sample intentionally has no receipt, so even a correctly scoped proposal must return `completed: false` / a waiting state.

## Deploy publicly on Render (recommended)

1. Create a GitHub repository named `safe-ai-mailroom` and push the files in this folder.
2. In Render, choose **New → Web Service**, connect that repository, and use:
   - Runtime: Python
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Health check path: `/health`
3. In Render → Environment, add `OPENAI_API_KEY` and set `OPENAI_MODEL` to a model available to your API account. Add the receipt verification secret/public key only if you have the real receipt issuer's scheme and key. Do not invent a key and expect platform-signed receipts to validate.
4. Deploy. Wait until Render reports the service as live.
5. Test these public URLs in a browser:
   - `https://YOUR-SERVICE.onrender.com/health`
   - `https://YOUR-SERVICE.onrender.com/.well-known/agent.json`
6. In the assignment box, enter **the full HTTPS action endpoint**, not the home page:

   `https://YOUR-SERVICE.onrender.com/v1/mailroom/actions`

7. Use **Check** first and inspect the response. Do not spend all checks on guesses; the page says the last check is reserved for **Save**. Once the endpoint passes the cases, click **Save** with a check still available.

Render's free service may sleep when idle, so the first request can take longer. The local SQLite file on a free instance is not a durable database across all redeploys; for the assignment's immediate validation it can work, but use a persistent disk or external database if audit history must survive restarts.

## Push from PowerShell

Run in the folder containing `main.py`:

```powershell
git init
git add .
git commit -m "Build safe AI mailroom agent"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/safe-ai-mailroom.git
git push -u origin main
```

If the repository already exists and you intentionally want to replace its remote branch, confirm the remote and branch first; do not force-push blindly.

## Smoke test a deployed endpoint

```powershell
python smoke_test.py https://YOUR-SERVICE.onrender.com
```

The script checks health, both Agent Card URLs, one correctly scoped approval, recipient mismatch, and expired approval. It does not consume any checks on the assignment website; it calls your endpoint directly.

## Important grading checks

- HTTPS public endpoint; use `/v1/mailroom/actions` in the assignment field.
- Current signed authority must match the requested **action + recipient + document/item**. A signed document alone is insufficient.
- Evidence must quote source text, not just provide a vague explanation.
- Stale/revoked/expired approval or a different recipient must not authorize the requested action.
- Never return `completed: true` just because the action was chosen or an unsigned receipt says it succeeded.
- A real receipt must match the same `case_id`, `action_id`, action and recipient and pass signature validation.
- Read the assignment's actual failing response carefully. If it specifies a different payload schema, update this adapter to that exact contract before using more checks.
