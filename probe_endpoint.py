"""Warm a Render service and test both fast and AI-triggering proposal requests.
Usage: python probe_endpoint.py https://YOUR-SERVICE.onrender.com
This contacts only your service and does NOT consume assignment checks.
"""
from __future__ import annotations
import json
import sys
import time
import urllib.error
import urllib.request
import uuid


def call(url: str, body: dict | None = None, timeout: float = 75.0):
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method="GET" if body is None else "POST")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read().decode("utf-8", errors="replace")
            return response.status, response.headers.get("Content-Type", ""), response.headers.get("X-Processing-Time-Ms", "n/a"), content, time.perf_counter() - started
    except urllib.error.HTTPError as exc:
        content = exc.read().decode("utf-8", errors="replace")
        return exc.code, exc.headers.get("Content-Type", ""), exc.headers.get("X-Processing-Time-Ms", "n/a"), content, time.perf_counter() - started


def make_case(case_id: str, force_ai: bool = False) -> dict:
    email = {"from": "manager@example.com", "body": ("Please review the attached note and handle this request for Maya; the report is mentioned in the note." if force_ai else "Please forward Q3-report.pdf to maya@example.com.")}
    if not force_ai:
        email.update({"to": "maya@example.com", "requested_action": "forward", "document": "Q3-report.pdf"})
    return {
        "dossierId": case_id, "inputDigest": "sha256:" + case_id, "email": email,
        "approval": {"signed": True, "signatureValid": True, "status": "current", "action": "forward", "recipient": "maya@example.com", "document": "Q3-report.pdf", "signer": "Operations Director", "provenance": "internal approval registry"},
        "caseState": "open",
        "permittedActions": [
            {"target": "mail.forward", "payload": {"to": "${recipient}", "item": "${item}"}},
            {"target": "mailroom.hold_for_review", "payload": {}}
        ]
    }


def verify_propose(base: str, case: dict, label: str, timeout: float = 25.0) -> bool:
    status, content_type, processing_ms, body, elapsed = call(base + "/v1/mailroom/actions", case, timeout=timeout)
    print(f"{label}: HTTP {status}; wall={elapsed:.2f}s; server={processing_ms}ms; Content-Type={content_type}")
    if "application/json" not in content_type.lower():
        print("FAIL: endpoint did not return application/json"); print(body[:1200]); return False
    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        print("FAIL: response is not valid JSON"); print(body[:1200]); return False
    proposals = result.get("proposals") if isinstance(result, dict) else None
    if status != 200 or result.get("ok") is not True or not isinstance(proposals, list) or len(proposals) != 1:
        print("FAIL: unexpected propose response envelope"); print(json.dumps(result, indent=2)[:2500]); return False
    print(f"ENVELOPE: PASS; contract={result.get('contractVersion')}; target={proposals[0].get('target')}")
    if elapsed > 10:
        print("WARNING: warm propose request took over 10 seconds; grader timeout may still be a risk.")
        return False
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python probe_endpoint.py https://YOUR-SERVICE.onrender.com")
        return 2
    base = sys.argv[1].rstrip("/")
    status, content_type, processing_ms, body, elapsed = call(base + "/health")
    print(f"HEALTH/WARM-UP: HTTP {status}; wall={elapsed:.2f}s; server={processing_ms}ms; Content-Type={content_type}")
    if status != 200:
        print(body[:1000]); return 1
    unique = uuid.uuid4().hex[:12]
    fast_ok = verify_propose(base, make_case("latency-fast-" + unique), "FAST PROPOSE")
    # Missing request action/recipient fields deliberately exercise the configured AI path.
    ai_ok = verify_propose(base, make_case("latency-ai-" + unique, force_ai=True), "AI-PATH PROPOSE")
    if fast_ok and ai_ok:
        print("OVERALL: PASS (both propose paths returned JSON envelopes within 10 seconds)")
        return 0
    print("OVERALL: FAIL — do not spend an assignment check until latency/response is resolved.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
