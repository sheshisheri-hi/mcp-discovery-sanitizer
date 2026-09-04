"""MCP discovery sanitizer — Stage-discovery gate, no LLM, no GPU.

Sit this in front of ``initialize`` / ``tools/list`` / prompts / resources
before an agent folds the payload into its system prompt.
"""

from mcp_discovery_sanitizer.hashutil import canonical_hash
from mcp_discovery_sanitizer.models import Policy, Reason, SanitizerResult, Verdict
from mcp_discovery_sanitizer.sanitize import sanitize_discovery

__all__ = [
    "Policy",
    "Reason",
    "SanitizerResult",
    "Verdict",
    "canonical_hash",
    "sanitize_discovery",
]

__version__ = "0.1.0"
