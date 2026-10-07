from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from .models import SecurityEvent


async def simulate_event_stream(
    events: list[SecurityEvent], delay_seconds: float = 0.5
) -> AsyncIterator[SecurityEvent]:
    """Replay telemetry deterministically for a judge/demo stream."""
    delay = max(0.0, min(float(delay_seconds), 10.0))
    for event in events:
        yield event
        if delay:
            await asyncio.sleep(delay)
