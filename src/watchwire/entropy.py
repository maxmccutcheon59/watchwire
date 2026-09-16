"""Shannon entropy helpers for high-entropy string detection."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Return Shannon entropy (bits/char) of *data*."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_high_entropy(token: str, *, min_length: int = 20, threshold: float = 4.5) -> bool:
    """True if *token* is long enough and entropy exceeds *threshold*."""
    if len(token) < min_length:
        return False
    return shannon_entropy(token) >= threshold
