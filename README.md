# Safe AI Mailroom Agent

A public HTTPS FastAPI service for the Safe AI Mailroom assignment (build 2.2.0). It reads mail/request and approval sources, checks signed/current/provenance-backed authority against the exact action, recipient, item and case state, emits one auditable proposal per dossier, and never sends email or executes external actions. It records completion only after verifying a cryptographic terminal receipt that matches the stored proposal.

## Endpoints

- `POST /v1/mailroom/actions` — propose exactly one action per dossier.
- `POST /v1/mailroom/propose` — alias for the proposal endpoint.
- `POST /v1/mailroom/commit` — validate and commit a signed terminal receipt.
- `POST /v1/mailroom/actions/commit` — alias for commit.
- `POST /v1/mailroom/actions/{callId}/commit` — commit receipt for one call.
- `GET /v1/mailroom/actions/{callId}` — read stored proposal state.
- `GET /v1/mailroom/audit/{dossierId}` — read the audit records for a dossier.
- `GET /health` and `/healthz` — health/database status.
- `GET /.well-known/agent.json` and `/.well-known/agent-card.json` — public agent metadata.


## Latency / deployment check

Before spending an assignment check, run `python probe_endpoint.py https://YOUR-SERVICE.onrender.com`. It warms a free Render instance using `/health`, then sends a small valid JSON proposal request and reports the POST latency, HTTP status, `Content-Type`, and response-envelope validity. A cold start can take much longer than a warm request on Render Free; invoke the grader immediately after the probe.

The proposal path has bounded AI timeout (6 seconds by default; one attempt only) and bounded concurrent AI calls. Referenced case-file URLs are fetched concurrently with a short per-file timeout, and dossiers are processed concurrently while preserving result order. This avoids serializing all network/model delays behind one proposal. If AI extraction times out or fails, the deterministic policy path remains fail-closed; do not treat an AI timeout as approval.

## Proposal request

The API accepts a single dossier or a batch. A dossier should include its own stable `dossierId` and `inputDigest`, request/mail source, approval/authority source, case state, and permitted action definitions. The parser supports common field names; a supplied action menu is preferred over invented targets.

Example:

```json
{
  "requestId": "req-001",
  "dossiers": [
    {
      "dossierId": "case-104",
      "inputDigest": "sha256:source-digest-104",
      "email": {
        "from": "manager@example.com",
        "to": "maya@example.com",
        "requested_action": "forward",
        "document": "Q3-report.pdf",
        "body": "Please forward Q3-report.pdf to maya@example.com."
      },
      "approval": {
        "signed": true,
        "signatureValid": true,
        "status": "current",
        "action": "forward",
        "recipient": "maya@example.com",
        "document": "Q3-report.pdf",
        "signer": "Operations Director",
        "provenance": "internal approval registry"
      },
      "caseState": "open",
      "permittedActions": [
        { "target": "mail.forward", "payload": { "to": "${recipient}", "item": "${item}" } },
        { "target": "mailroom.hold_for_review", "payload": {} }
      ]
    }
  ]
}
```

Example response shape:

```json
{
  "ok": true,
  "contractVersion": "mailroom.proposal.v2",
  "requestId": "req-001",
  "proposals": [
    {
      "dossierId": "case-104",
      "inputDigest": "sha256:source-digest-104",
      "callId": "call_<stable-id>",
      "target": "mail.forward",
      "payload": { "to": "maya@example.com", "item": "Q3-report.pdf" },
      "proposal": { "target": "mail.forward", "payload": { "to": "maya@example.com", "item": "Q3-report.pdf" } },
      "evidence": [],
      "authorized": true,
      "decision": "authorized",
      "audit": { "state": "proposed", "executionPerformed": false }
    }
  ],
  "audit": { "proposalCount": 1, "executionPerformed": false, "outboundCalls": 0, "outboundCanaryCap": 0 }
}
```

The example `evidence` list is abbreviated here; real response citations contain the source file, line/path, quoted source text and the fact each quote supports. The `actions` field mirrors `proposals` for clients that label action proposals separately. `target` and `payload` are drawn from the supplied menu when one is present; payload contains only the documented argument keys for that target.

## Safety rules

- A current status alone is not enough. Authority must be signed/verified, provenance-backed and match the exact requested action, recipient and requested document/item.
- Expired, revoked, superseded, stale or conflicting authority state takes precedence over an optimistic status.
- Already completed/sent/delivered cases are not proposed for a second outbound action.
- A mismatch or missing authority selects a safe permitted review/hold action when available. The service never invokes email, messaging, payment, or other external tools; `outboundCalls` and `outboundCanaryCap` are always zero.
- Evidence quotes are copied from supplied inputs or fetched case files. Generic filler lines are not added when a relevant citation is missing.
- Malformed JSON is rejected with HTTP 400; empty/invalid request envelopes are rejected with HTTP 422.
- Idempotency keys return a stable response for identical requests and HTTP 409 when reused for a different body. Conflicting call ID or receipt replays return HTTP 409.
- Invalid/unsigned/mismatched/nonterminal receipts are rejected and never mark a proposal complete.

## Receipt verification

Set one verification mechanism only when it matches the actual receipt issuer:

### HMAC-SHA256

Set `RECEIPT_HMAC_SECRET` in Render's Environment settings. The issuer must sign canonical JSON encoded as UTF-8 with keys sorted and separators `(',', ':')`, excluding the signature and algorithm/verification metadata fields. Signature is hexadecimal HMAC-SHA256 (optionally prefixed `sha256=`).

### Ed25519

Alternatively, set `RECEIPT_PUBLIC_KEY` to the trusted issuer's PEM public key, and use an `ed25519` signature (hex or base64). Do not place a private key in this service. Do not trust a `verified: true` field as proof of a signature. If the assignment supplies a different verifier/key/signature scheme, implement that exact documented scheme; do not invent a secret or bypass verification.

The commit request shape is:

```json
{
  "callId": "call_<value-from-proposal>",
  "inputDigest": "<exact-digest-from-proposal>",
  "receipt": {
    "dossierId": "<exact-dossierId>",
    "callId": "call_<value-from-proposal>",
    "inputDigest": "<exact-digest-from-proposal>",
    "target": "mail.forward",
    "payload": { "to": "maya@example.com", "item": "Q3-report.pdf" },
    "status": "delivered",
    "signature_algorithm": "hmac-sha256",
    "signature": "<issuer-generated-signature>"
  }
}
```

All receipt IDs, digest, target and payload must match the stored proposal exactly, and the receipt must describe a terminal success state.

## Run locally (PowerShell)

```powershell
cd safe-ai-mailroom
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:DATABASE_PATH = ".\mailroom_audit.sqlite3"
$env:RECEIPT_HMAC_SECRET = "local-test-secret"
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Set `OPENAI_API_KEY` if you want the optional model-assisted extraction of natural-language mail. Normal code, not the model, makes the authority decision, validates inputs, writes the audit log, and verifies receipts. No API key means deterministic parsing and conservative hold-for-review behavior for ambiguous cases.

## Deployment on Render

The current repository includes a `Dockerfile` and works as a Render Docker Web Service.

- Repository: `24F2009112/safe-ai-mailroom`
- Branch: `main`
- Root directory: blank (repository root)
- Docker build context: `.`
- Dockerfile path: `./Dockerfile`
- Health check path: `/health`
- Free instance is sufficient for evaluation, but it may spin down while idle.

Recommended environment settings:

- `OPENAI_API_KEY` — valid key if using model-assisted extraction.
- `OPENAI_MODEL` — a model available to the API account, e.g. `gpt-4o-mini`.
- `DATABASE_PATH` — `./mailroom_audit.sqlite3`.
- `RECEIPT_HMAC_SECRET` or `RECEIPT_PUBLIC_KEY` — only the real trusted receipt-verification mechanism supplied by the assignment.

Never put secrets in GitHub. SQLite on a free instance is not durable across every restart/redeploy; the proposal/commit replay checks persist within the current instance storage.

## Smoke test

```powershell
python smoke_test.py https://YOUR-SERVICE.onrender.com
```

This calls the service directly and does not consume assignment checks. It checks the proposal envelope, one proposal per dossier, exact IDs/digests, arguments, evidence presence, strict scope rejection, idempotency/stable reuse, conflict rejection, malformed-request rejection, and invalid receipt rejection. Receipt-commit success also requires a correctly configured trusted verification key and a valid issuer-generated signed receipt.

## Push the updated version

From this folder in PowerShell, the safe normal update is:

```powershell
git add main.py smoke_test.py README.md
git commit -m "Fix mailroom proposal contract and safety checks"
git push origin main
```

Wait for Render to redeploy and show **Live**, then rerun the smoke test before using another assignment Check. The assignment feedback is the final authority for whether its hidden contract accepts this adapter. Save a check for the final Save action.
