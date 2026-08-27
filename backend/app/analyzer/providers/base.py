"""Provider interface.

The engine depends on this, never on a concrete SDK. Swapping Gemini for
Claude (or adding a local model) is a one-line change in `build_provider`,
and the eval suite is what tells you whether the swap was a good idea.
"""

from __future__ import annotations

from typing import Protocol

from ..schema import ModelVerdict


class VerdictProvider(Protocol):
    """Turns a message into a ModelVerdict, or None on any failure.

    Contract: implementations MUST NOT raise. A provider that throws takes
    the whole extension down; a provider that returns None degrades to
    link-checks-only, which is still useful to the user.
    """

    name: str

    async def verdict(self, system: str, user: str) -> ModelVerdict | None: ...
