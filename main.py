import json, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8738
UPSTREAM_URL = "http://localhost:18090/v1"

metrics_data = {"total_requests": 0, "blocked_requests": 0, "allowed_requests": 0, "errors": 0, "by_action": {}, "blocked_patterns_hit": {}, "recent_interceptions": []}
metrics_lock = threading.Lock()

ALLOWED_ACTIONS_DEFAULT = {"chat-messages:invoke", "models:list", "chat-messages:stream"}
BLOCKED_PATTERNS_DEFAULT = ["DROP TABLE", "rm -rf /", "ignore previous instructions", "disregard your rules", "<script>" ]

class PolicyManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._allowed_actions = set(ALLOWED_ACTIONS_DEFAULT)
        self._blocked_patterns = list(BLOCKED_PATTERNS_DEFAULT)
    # ... (truncated for brevity)
    def add_blocked_pattern(self, pattern):
        with self._lock:
            if pattern not in self._blocked_patterns:
                self._blocked_patterns.append(pattern)
                return True
            return False

policy_manager = PolicyManager()

class PolicyDecision:
    def __init__(self, allowed, reason="", action=""):
        self.allowed = allowed
        self.reason = reason
        self.action = action
    def to_dict(self):
        return {"allowed": self.allowed, "reason": self.reason, "action": self.action}

# ... (more code)

class AuditLogger:
    def __init__(self):
        self.events: list[dict] = []
    def log(self, event, **details):
        entry = {"ts": time.time(), "event": event, **details}
        self.events.append(entry)
        print(f"[AUDIT] {json.dumps(entry)}")
    def recent(self, limit=50):
        return self.events[-limit:]

audit = AuditLogger()

class MetricsTracker:
    def get_summary(self):
        with metrics_lock:
            total = metrics_data["total_requests"]
            rate_limited = metrics_data["blocked_requests"]
            success_rate = f"{round((metrics_data['allowed_requests']/max(1,total))*100, 1)}%"
            return {"server": {"host": GATEWAY_HOST, "port": GATEWAY_PORT, "strategy": "security_gateway"},
                    "summary": {"total_requests": total, "allowed_requests": metrics_data["allowed_requests"], "blocked_requests": rate_limited, "success_rate": success_rate},
                    "policy": {"allowed_actions": list(policy_manager.get_allowed_actions()), "blocked_patterns_count": len(policy_manager.get_blocked_patterns())},
                    "interceptions": metrics_data["blocked_patterns_hit"],
                    "recent_events": metrics_data["recent_interceptions"][-20:],
                    "by_action": metrics_data["by_action"]}

metrics_tracker = MetricsTracker()

class HumanApproval:
    def __init__(self):
        self.auto_approve = True
    def request(self, decision, body):
        audit.log("hitl_approval", action=decision.action, allowed=decision.allowed, reason=decision.reason, auto_approve=self.auto_approve)
        return self.auto_approve if not decision.allowed else True

class GatewayHandler(BaseHTTPRequestHandler):
    upstream_url = UPSTREAM_URL
    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON body"})
            return {}
    def _respond(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    # ... (truncated)
    def do_GET(self):
        parsed = urlparse(self.path)
        path_only = parsed.path
        if path_only == "/" or path_only == "/index.html":
            self._serve_dashboard()
            return
        if path_only == "/api/status":
            summary = metrics_tracker.get_summary()
            self._respond(200, summary)
            return
        if path_only == "/api/audit":
            limit = int(parsed.query.split("limit=")[1]) if "limit=" in parsed.query else 50
            logs = audit.recent(limit)
            self._respond(200, {"logs": logs})
            return
        if path_only == "/api/policy/actions":
            if self.command == "GET":
                actions = policy_manager.get_allowed_actions()
                self._respond(200, {"actions": list(actions)})
            elif self.command == "POST":
                body = self._read_body()
                new_actions = body.get("actions", [])
                policy_manager.set_allowed_actions(new_actions)
                self._respond(200, {"updated": True, "actions": new_actions})
            return
        if path_only == "/api/policy/blocked-patterns":
            # ... handling
            return
        decision = evaluate_policy("GET", self.path, {})
        audit.log("request", method="GET", path=self.path, decision=decision.to_dict())
        action = _map_route("GET", self.path)
        record_metric("request", not decision.allowed, action=action)
        if not decision.allowed:
            approval = HumanApproval().request(decision, {})
            if not approval:
                self._respond(403, decision.to_dict())
                return
        self._forward(decision, {})
    def do_POST(self):
        # ...
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
    def do_PUT(self):
        # ...
    def do_DELETE(self):
        # ...
    def _serve_dashboard(self):
        html = """<!DOCTYPE html>..."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode())))
        self.end_headers()
        self.wfile.write(html.encode())
    def log_message(self, fmt, *args):
        pass

def main():
    server = ThreadingHTTPServer((GATEWAY_HOST, GATEWAY_PORT), GatewayHandler)
    print(f"Agent Security Gateway listening on {GATEWAY_HOST}:{GATEWAY_PORT}")
    print(f"Dashboard: http://{GATEWAY_HOST}:{GATEWAY_PORT}/")
    print(f"API Status: http://{GATEWAY_HOST}:{GATEWAY_PORT}/api/status")
    print(f"Upstream: {UPSTREAM_URL}")
    print("\nPress Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()

if __name__ == "__main__":
    main()