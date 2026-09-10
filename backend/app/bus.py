import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from app.schemas import Event


class Broadcaster:
    """Simple in-memory pub/sub. Honeypot services publish events,
    consumers (pipeline, websocket clients) subscribe to them.
    """

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def publish(self, event: Event) -> None:
        self._deliver(event)

    def publish_soon(self, event: Event) -> None:
        """Sync version of publish() for callbacks that can't await
        (e.g. asyncssh's validate_password).
        """
        self._deliver(event)

    def _deliver(self, event: Event) -> None:
        for queue in self._subscribers:
            queue.put_nowait(event)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[AsyncIterator[Event]]:
        """Subscribe for the duration of the `async with` block.

        The queue is removed when the block exits, even if the stream
        was never iterated.
        """
        queue: asyncio.Queue[Event] = asyncio.Queue()
        self._subscribers.add(queue)
        try:
            yield self._stream(queue)
        finally:
            self._subscribers.discard(queue)

    @staticmethod
    async def _stream(queue: asyncio.Queue[Event]) -> AsyncIterator[Event]:
        while True:
            yield await queue.get()
