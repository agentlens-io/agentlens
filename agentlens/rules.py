"""
Rule-based danger detection for tool_use events.
Deliberately NOT using an LLM — detection must be deterministic and auditable.
"""
import re
from dataclasses import dataclass
from typing import Optional
from .models import ToolUseEvent


@dataclass
class Violation:
    rule_id: str
    severity: str        # "critical" | "high" | "medium"
    description: str
    matched_value: str   # the exact string that triggered the rule


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

# Shell commands that are almost never legitimate in an agent
_SHELL_BLOCKLIST = [
    (r"rm\s+-rf?\s+/",          "critical", "SHELL_RM_ROOT",    "Recursive delete from filesystem root"),
    (r"rm\s+-rf?\s+~",          "critical", "SHELL_RM_HOME",    "Recursive delete from home directory"),
    (r":\(\)\{.*\|.*&\};:",     "critical", "SHELL_FORK_BOMB",  "Fork bomb pattern"),
    (r"curl\s+.+\|\s*(ba)?sh",  "critical", "SHELL_CURL_PIPE",  "Piping curl output to shell"),
    (r"wget\s+.+\|\s*(ba)?sh",  "critical", "SHELL_WGET_PIPE",  "Piping wget output to shell"),
    (r"chmod\s+777",            "high",     "SHELL_CHMOD_777",  "Setting world-writable permissions"),
    (r"sudo\s+",                "high",     "SHELL_SUDO",       "Privilege escalation via sudo"),
    (r">\s*/etc/",              "high",     "SHELL_WRITE_ETC",  "Writing to /etc/"),
    (r">\s*/root/",             "high",     "SHELL_WRITE_ROOT", "Writing to /root/"),
    (r"dd\s+if=",               "high",     "SHELL_DD",         "Raw disk operation"),
    (r"mkfs\.",                 "critical", "SHELL_MKFS",       "Filesystem format command"),
    (r"shutdown|poweroff|reboot","high",    "SHELL_SHUTDOWN",   "System shutdown/reboot"),
    (r"iptables\s+",            "high",     "SHELL_IPTABLES",   "Firewall rule modification"),
    (r"crontab\s+-",            "high",     "SHELL_CRONTAB",    "Cron modification"),
]

# Sensitive file paths being accessed
_PATH_BLOCKLIST = [
    (r"\.ssh/(id_rsa|id_ed25519|authorized_keys)", "critical", "PATH_SSH_KEY",     "SSH private key access"),
    (r"/etc/passwd",                               "critical", "PATH_PASSWD",      "Password file access"),
    (r"/etc/shadow",                               "critical", "PATH_SHADOW",       "Shadow password file access"),
    (r"\.aws/credentials",                         "critical", "PATH_AWS_CREDS",   "AWS credentials access"),
    (r"\.env",                                     "high",     "PATH_ENV_FILE",    "Environment file access"),
    (r"/proc/self",                                "high",     "PATH_PROC_SELF",   "Process self introspection"),
]

# Credential-like patterns in any field value
_CREDENTIAL_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}",                          "critical", "CRED_AWS_KEY",     "AWS access key ID"),
    (r"sk-[A-Za-z0-9]{32,}",                       "critical", "CRED_OPENAI_KEY",  "OpenAI API key"),
    (r"sk-ant-[A-Za-z0-9\-]{32,}",                 "critical", "CRED_ANTHROPIC_KEY","Anthropic API key"),
    (r"ghp_[A-Za-z0-9]{36}",                       "critical", "CRED_GITHUB_PAT",  "GitHub personal access token"),
    (r"xox[baprs]-[A-Za-z0-9\-]+",                "high",     "CRED_SLACK_TOKEN", "Slack token"),
]


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

def _flatten(value, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a nested dict/list."""
    if depth > 8:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out = []
        for v in value.values():
            out.extend(_flatten(v, depth + 1))
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_flatten(item, depth + 1))
        return out
    return []


def check(event: ToolUseEvent) -> list[Violation]:
    """
    Run all rules against a ToolUseEvent.
    Returns a (possibly empty) list of Violations.
    Pure function — no side effects.
    """
    violations: list[Violation] = []

    tool_name = (event.tool_name or "").lower()
    all_input_strings = _flatten(event.tool_input)
    combined = " ".join(all_input_strings)

    is_shell = tool_name in ("bash", "shell", "terminal", "exec", "run", "computer")

    # Shell command rules
    if is_shell:
        for pattern, severity, rule_id, description in _SHELL_BLOCKLIST:
            if re.search(pattern, combined, re.IGNORECASE):
                match = re.search(pattern, combined, re.IGNORECASE)
                violations.append(Violation(
                    rule_id=rule_id,
                    severity=severity,
                    description=description,
                    matched_value=match.group(0) if match else "",
                ))

    # Path rules — applied to all tools
    for pattern, severity, rule_id, description in _PATH_BLOCKLIST:
        if re.search(pattern, combined, re.IGNORECASE):
            match = re.search(pattern, combined, re.IGNORECASE)
            violations.append(Violation(
                rule_id=rule_id,
                severity=severity,
                description=description,
                matched_value=match.group(0) if match else "",
            ))

    # Credential patterns — applied to all tools
    for pattern, severity, rule_id, description in _CREDENTIAL_PATTERNS:
        if re.search(pattern, combined):
            match = re.search(pattern, combined)
            violations.append(Violation(
                rule_id=rule_id,
                severity=severity,
                description=description,
                matched_value=match.group(0)[:8] + "..." if match else "",  # partial only
            ))

    return violations
