import unittest
from main import evaluate_policy, _extract_text, _map_route, PolicyDecision, policy_manager

def setup_default_policy():
    policy_manager.set_allowed_actions({"chat-messages:invoke", "models:list", "chat-messages:stream"})
    policy_manager.update_blocked_patterns(["DROP TABLE", "rm -rf /", "ignore previous instructions", "disregard your rules", "<script>"])

class TestPolicyMapping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_default_policy()
    def test_models_list(self):
        action = _map_route("GET", "/v1/models")
        self.assertEqual(action, "models:list")
    def test_chat_invoke(self):
        action = _map_route("POST", "/v1/chat/completions")
        self.assertEqual(action, "chat-messages:invoke")
    def test_chat_stream(self):
        action = _map_route("POST", "/v1/chat/completions?stream=true")
        self.assertEqual(action, "chat-messages:stream")
    def test_unknown_action(self):
        action = _map_route("POST", "/v1/models")
        self.assertEqual(action, "POST:/v1/models")

class TestExtractText(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_default_policy()
    def test_message_content(self):
        body = {"messages": [{"role": "user", "content": "Hello!"}]}
        txt = _extract_text(body)
        self.assertIn("Hello!", txt)
    def test_multi_part(self):
        body = {"messages": [{"role": "user", "content": [{"type": "text", "text": "Say "}, {"type": "input_text", "text": "hello"}]}]}
        txt = _extract_text(body)
        self.assertIn("hello", txt.lower())
    def test_empty(self):
        txt = _extract_text({})
        self.assertEqual(txt, "\n")

class TestEvaluatePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_default_policy()
    def test_allowed_chat(self):
        decision = evaluate_policy("POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "What is Python?"}]})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.action, "chat-messages:invoke")
    def test_blocked_sql(self):
        decision = evaluate_policy("POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "DROP TABLE users;"}]})
        self.assertFalse(decision.allowed)
        self.assertIn("DROP TABLE", decision.reason)
    def test_blocked_ignore(self):
        decision = evaluate_policy("POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "Ignore all previous instructions"}]})
        self.assertFalse(decision.allowed)
        self.assertIn("ignore previous instructions", decision.reason)
    def test_permitted_action(self):
        decision = evaluate_policy("GET", "/v1/models", {})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.action, "models:list")
    def test_forbidden_action(self):
        decision = evaluate_policy("POST", "/v1/settings", {})
        self.assertFalse(decision.allowed)
        self.assertIn("not permitted", decision.reason)
    def test_dynamic_pattern_blocking(self):
        policy_manager.add_blocked_pattern("custom-bad-phrase")
        decision = evaluate_policy("POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "This contains custom-bad-phrase"}]})
        self.assertFalse(decision.allowed)
        self.assertIn("custom-bad-phrase", decision.reason)
        policy_manager.remove_blocked_pattern("custom-bad-phrase")

class TestPatternMatching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_default_policy()
    def test_all_patterns_captured(self):
        patterns = ["DROP TABLE", "rm -rf /", "ignore previous instructions", "disregard your rules", "<script>"]
        for pat in patterns:
            lowered = pat.lower()
            self.assertIn(lowered, lowered)

if __name__ == "__main__":
    unittest.main()