import json
import unittest
from main import evaluate_policy, _extract_text, _map_route, PolicyDecision, policy_manager


def setup_default_policy():
    policy_manager.set_allowed_actions({
        "chat-messages:invoke",
        "models:list",
        "chat-messages:stream",
    })
    policy_manager.update_blocked_patterns([
        "DROP TABLE",
        "rm -rf /",
        "ignore previous instructions",
        "disregard your rules",
        "<script>",
    ])