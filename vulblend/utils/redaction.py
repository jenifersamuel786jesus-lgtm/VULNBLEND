from __future__ import annotations

import re

SECRET_PATTERNS = [re.compile(r"(?i)(password|token|secret|authorization|cookie)\s*[:=]\s*[^,;\s]+"), re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]+")]

def redact(text: str | None) -> str:
    value = str(text or "")
    for pattern in SECRET_PATTERNS:
        value = pattern.sub(lambda match: match.group(0).split(":")[0] + ": [REDACTED]", value)
    return value[:10000]
