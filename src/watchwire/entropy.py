"""Shannon entropy helpers for high-entropy string detection.

Known false-positive classes (filtered by :func:`is_known_fp_token`):

* UUIDs (with or without dashes)
* Pure hexadecimal runs of length ≥ 32 (MD5 / SHA-1 / SHA-256 / SHA-512,
  git object ids, UUID-nodash) — lockfile hashes are also excluded via
  default ``**/*.lock`` globs in the policy file
* Very low alphabet diversity after stripping base64 padding (e.g. ``AAAA…==``)
"""

from __future__ import annotations

import math
import re
from collections import Counter

# RFC 4122 UUID with dashes.
_UUID_DASHED = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Pure hex (hashes / UUID without dashes).
_PURE_HEX = re.compile(r"^[0-9a-fA-F]+$")


def shannon_entropy(data: str) -> float:
    """Return Shannon entropy (bits/char) of *data*."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_known_fp_token(token: str) -> bool:
    """True if *token* matches a documented false-positive class.

    These should not emit ``high_entropy`` findings even when Shannon entropy
    is high (hex hashes are near-max entropy by construction).
    """
    if not token:
        return False
    if _UUID_DASHED.fullmatch(token):
        return True
    stripped = token.rstrip("=")
    if len(stripped) >= 32 and _PURE_HEX.fullmatch(stripped):
        return True
    # Base64 padding / filler noise: almost no unique symbols.
    if len(stripped) >= 20 and len(set(stripped.lower())) <= 3:
        return True
    return False


def looks_high_entropy(
    token: str,
    *,
    min_length: int = 20,
    threshold: float = 4.5,
) -> bool:
    """True if *token* looks like a high-entropy secret (not a known FP)."""
    if len(token) < min_length:
        return False
    if is_known_fp_token(token):
        return False
    return shannon_entropy(token) >= threshold
