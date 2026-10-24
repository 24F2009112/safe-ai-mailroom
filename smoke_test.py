"""Public endpoint smoke test. Usage: python smoke_test.py https://service.onrender.com"""
from __future__ import annotations
import json
import sys
import urllib.error
import urllib.request


def get_json(url: str, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            payload = response.read().decode("utf-8")
            return response.status, json.loads(payload)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"raw": "HTTP error response was not JSON"}
        return exc.code, payload


def check(name: str, condition: bool, details: str = "") -> bool:
    print(("PASS" if condition else "FAIL") + " " + name + (f" — {details}" if details else ""))
    return condition


def case(case_id: str, requested_recipient: str, approval_recipient: str, status: str = "current") -> dict:
    return {
        "case_id": case_id,
        "email": {
            "from": "manager@example.com",
            "to": requested_recipient,
            "requested_action": "forward",
            "document": "Q3-report.pdf",
            "body": f"Please forward Q3-report.pdf to {requested_recipient}.",
        },
        "approval": {
            "signed": True,
            "signer": "Operations Director",
            "status": status,
            "action": "forward",
            "recipient": approval_recipient,
            "document": "Q3-report.pdf",
        },
        "permitted_actions": ["forward", "hold_for_review", "request_clarification"],
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python smoke_test.py https://YOUR-SERVICE.onrender.com")
        return 2
    base = sys.argv[1].rstrip("/")
    ok = True
    status, health = get_json(base + "/health")
    ok &= check("health endpoint", status == 200 and health.get("status") == "ok", f"HTTP {status}")

    for path in ("/.well-known/agent.json", "/.well-known/agent-card.json"):
        status, card = get_json(base + path)
        ok &= check("Agent Card " + path, status == 200 and card.get("name") == "Safe AI Mailroom Agent", f"HTTP {status}")

    status, good = get_json(base + "/v1/mailroom/actions", "POST", case("smoke-good", "maya@example.com", "maya@example.com", "current"))
    good_condition = (
        status == 200
        and good.get("ok") is True
        and good.get("authority_check", {}).get("authorized") is True
        and good.get("action") == "forward"
        and good.get("completed") is False
        and bool(good.get("evidence"))
    )
    ok &= check("current matching authority + evidence + await receipt", good_condition, f"HTTP {status}, action={good.get('action')}, authorized={good.get('authority_check', {}).get('authorized')}, completed={good.get('completed')}")

    status, mismatch = get_json(base + "/v1/mailroom/actions", "POST", case("smoke-mismatch", "maya@example.com", "other@example.com", "current"))
    mismatch_condition = status == 200 and mismatch.get("authority_check", {}).get("authorized") is False and mismatch.get("action") in {"hold", "hold_for_review", "clarify", "request_clarification", "defer", "reject", "escalate", "no_action", "needs_review", "review_manually"}
    ok &= check("recipient mismatch is not authorized", mismatch_condition, f"HTTP {status}, action={mismatch.get('action')}, authorized={mismatch.get('authority_check', {}).get('authorized')}")

    status, expired = get_json(base + "/v1/mailroom/actions", "POST", case("smoke-expired", "maya@example.com", "maya@example.com", "expired"))
    expired_condition = status == 200 and expired.get("authority_check", {}).get("authorized") is False and expired.get("completed") is False
    ok &= check("expired approval is blocked", expired_condition, f"HTTP {status}, status={expired.get('authority_check', {}).get('approval_status')}, authorized={expired.get('authority_check', {}).get('authorized')}")

    not_approved_payload = case("smoke-not-approved", "maya@example.com", "maya@example.com", "not approved")
    status, not_approved = get_json(base + "/v1/mailroom/actions", "POST", not_approved_payload)
    not_approved_condition = status == 200 and not_approved.get("authority_check", {}).get("authorized") is False and not_approved.get("completed") is False
    ok &= check("not-approved status is blocked", not_approved_condition, f"HTTP {status}, status={not_approved.get('authority_check', {}).get('approval_status')}, authorized={not_approved.get('authority_check', {}).get('authorized')}")

    print("\nOverall:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
