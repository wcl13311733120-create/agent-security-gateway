"""
Agent Security Gateway — MVP
An OpenAI protocol compatible proxy that filters requests/responses
through a policy engine before forwarding to upstream providers.
Built on Python 3 stdlib only.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin
from urllib.request import Request, urlopen

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8738
UPSTREAM_URL = "http://localhost:8080/v1"  # example upstream endpoint

# ---------------------------------------------------------------
# Policy Engine (Policy-as-Code): simple action catalog + rules
# ---------------------------------------------------------------

ALLOWED_ACTIONS = {
    "chat-messages:invoke",
    "models:list",
    "chat-messages:stream",
}

BLOCKED_PATTERNS = [
    "DROP TABLE",
    "rm -rf /",
    "ignore previous instructions",
    "disregard your rules",
    "<script>",
]


class PolicyDecision:
    """Result of evaluating an action against the policy set."""
    def __init__(self, allowed: bool, reason: str = "", action: str = ""):
        self.allowed = allowed
        self.reason = reason
        self.action = action

    def to_dict(self):
        return {"allowed": self.allowed, "reason": self.reason, "action": self.action}


def _pattern_matches_any(patterns: list[str], text: str) -> bool:
    """Return True if any pattern's words all appear in text (order‑agnostic)."""
    lowered = text.lower()
    for pat in patterns:
        pat_words = pat.lower().split()
        t_words = set(lowered.split())
        if all(word in t_words for word in pat_words):
            return True
    return False


def evaluate_policy(method: str, path: str, body: dict) -> PolicyDecision:
    """
    Evaluate an inbound request against the action catalog + guard rules.

    Rules:
      1. The route maps to a permitted action in the catalog.
      2. Request bodies must not contain blocked prompt-injection patterns.
    """
    action = _map_route(method, path)
    if action not in ALLOWED_ACTIONS:
        return PolicyDecision(False, f"Action '{action}' is not permitted.", action)

    text = _extract_text(body)
    if _pattern_matches_any(BLOCKED_PATTERNS, text):
        # Find which pattern matched for the reason message
        for pat in BLOCKED_PATTERNS:
            pat_words = pat.lower().split()
            t_words = set(text.lower().split())
            if all(word in t_words for word in pat_words):
                return PolicyDecision(
                    False,
                    f"Blocked pattern detected: {pat}",
                    action,
                )

    return PolicyDecision(True, "OK", action)


def _map_route(method: str, path: str) -> str:
    """Map an HTTP route to an action-catalog identifier."""
    path_only = path.split("?")[0]
    query = path.split("?", 1)[1] if "?" in path else ""
    is_stream = "stream=true" in query
    if method == "GET" and path_only.endswith("/models"):
        return "models:list"
    if method == "POST" and path_only.endswith("/chat/completions"):
        if is_stream:
            return "chat-messages:stream"
        return "chat-messages:invoke"
    return f"{method}:{path_only}"


def _extract_text(body: dict) -> str:
    """Pull all user-provided text out of an OpenAI-style body."""
    chunks = []
    if isinstance(body, dict):
        messages = body.get("messages", [])
        if isinstance(messages, list):
            for msg in messages:
                content = msg.get("content", "") if isinstance(msg, dict) else ""
                if isinstance(content, str):
                    chunks.append(content)
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and "text" in part:
                            chunks.append(part["text"])
    return "\n".join(chunks)


# ---------------------------------------------------------------
# Audit Logger — full-chain trace per request
# ---------------------------------------------------------------

class AuditLogger:
    def __init__(self):
        self.events: list[dict] = []

    def log(self, event: str, **details):
        entry = {
            "ts": time.time(),
            "event": event,
            **details,
        }
        self.events.append(entry)
        print(f"[AUDIT] {json.dumps(entry)}")

    def recent(self, limit: int = 50) -> list[dict]:
        return self.events[-limit:]


audit = AuditLogger()


# ---------------------------------------------------------------
# HITL Approval gate (simple in-process stub)
# ---------------------------------------------------------------

class HumanApproval:
    """
    Human-in-the-loop approval gate.

    In a production deployment this would block and prompt real
    operators — for the MVP we auto-approve after logging so the
    gateway remains non-blocking while the hook is visible.
    """

    def __init__(self):
        self.auto_approve = True

    def request(self, decision: PolicyDecision, body: dict) -> bool:
        audit.log(
            "hitl_approval",
            action=decision.action,
            allowed=decision.allowed,
            reason=decision.reason,
            auto_approve=self.auto_approve,
        )
        return self.auto_approve if not decision.allowed else True


# ---------------------------------------------------------------
# HTTP Proxy Handler
# ---------------------------------------------------------------

class GatewayHandler(BaseHTTPRequestHandler):
    upstream_url = UPSTREAM_URL

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON body"})
            return {}

    def _respond(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self, decision: PolicyDecision, body: dict):
        """Forward the validated request to the upstream /v1 endpoint."""
        upstream = urljoin(self.upstream_url, self.path)
        req = Request(upstream, method=self.command, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, data=json.dumps(body).encode() if body else None) as resp:
                upstream_body = resp.read()
                self.send_response(resp.status)
                ctype = resp.headers.get("Content-Type", "application/json")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(upstream_body)))
                self.end_headers()
                self.wfile.write(upstream_body)
                audit.log("upstream_response", status=resp.status, upstream=upstream)
        except Exception as exc:
            audit.log("upstream_error", error=str(exc))
            self._respond(502, {"error": f"upstream error: {exc}"})

    def do_GET(self):
        decision = evaluate_policy("GET", self.path, {})
        audit.log("request", method="GET", path=self.path, decision=decision.to_dict())
        if not decision.allowed:
            approval = HumanApproval().request(decision, {})
            if not approval:
                self._respond(403, decision.to_dict())
                return
        self._forward(decision, body)

    def do_POST(self):
        body = self._read_body()
        if not body:
            return  # error already sent
        decision = evaluate_policy("POST", self.path, body)
        audit.log("request", method="POST", path=self.path, decision=decision.to_dict())
        if not decision.allowed:
            approval = HumanApproval().request(decision, body)
            if not approval:
                self._respond(403, decision.to_dict())
                return
        self._forward(decision, body)

    def log_message(self, fmt, *args):
        # keep stdout clean — rely on AuditLogger instead
        pass


def main():
    server = ThreadingHTTPServer((GATEWAY_HOST, GATEWAY_PORT), GatewayHandler)
    print(f"Agent Security Gateway listening on {GATEWAY_HOST}:{GATEWAY_PORT}")
    print(f"Upstream: {UPSTREAM_URL}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
