import asyncio

from app.bus import Broadcaster
from app.schemas import Event


def make_event(**overrides) -> Event:
    defaults = dict(
        sensor_id="hive-dev",
        service="ssh",
        event_type="auth_attempt",
        source_ip="203.0.113.7",
    )
    return Event(**{**defaults, **overrides})


async def test_subscriber_receives_published_event():
    bus = Broadcaster()
    event = make_event()

    async with bus.subscribe() as stream:
        await bus.publish(event)
        received = await asyncio.wait_for(stream.__anext__(), timeout=1)

    assert received == event


async def test_fan_out_to_multiple_subscribers():
    bus = Broadcaster()
    event = make_event(event_type="command")

    async with bus.subscribe() as stream_a, bus.subscribe() as stream_b:
        await bus.publish(event)

        assert await asyncio.wait_for(stream_a.__anext__(), timeout=1) == event
        assert await asyncio.wait_for(stream_b.__anext__(), timeout=1) == event


async def test_publish_with_no_subscribers_does_not_raise():
    bus = Broadcaster()
    await bus.publish(make_event())


async def test_subscriber_is_removed_on_context_exit():
    bus = Broadcaster()

    async with bus.subscribe():
        assert bus.subscriber_count == 1

    assert bus.subscriber_count == 0


async def test_queue_registered_before_consumer_starts_iterating():
    bus = Broadcaster()
    event = make_event(event_type="port_scan")

    async with bus.subscribe() as stream:
        await bus.publish(event)
        assert await asyncio.wait_for(stream.__anext__(), timeout=1) == event
