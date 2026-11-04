"""Guardrail hook. Replace this file with the real policy.

check(tool_name, args, context) -> dict(decision="allow"|"block", reason=str)

`args` is the model's raw tool input. `context` carries: case_id, surface, user_prompt,
history (the full message list so far, incl. prior tool results), and call_index.
The agent never executes a tool stub unless decision == "allow".
"""


def check(tool_name: str, args: dict, context: dict) -> dict:
    return {"decision": "allow", "reason": "pass-through stub"}
