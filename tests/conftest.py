"""Pytest configuration and shared fixtures for RACE Toolkit tests."""

import pytest
import asyncio
from typing import Callable


class MockTransport:
    """Mock transport for testing RACE protocol without hardware."""

    def __init__(self):
        self.sent_data: list[bytes] = []
        self.responses: list[bytes] = []
        self.recv_fn: Callable[[bytes], None] | None = None
        self._setup_called = False

    async def setup(self, recv_fn: Callable[[bytes], None]):
        self.recv_fn = recv_fn
        self._setup_called = True

    async def send(self, data: bytes):
        self.sent_data.append(data)
        # If there are queued responses, deliver the next one
        if self.responses and self.recv_fn:
            response = self.responses.pop(0)
            self.recv_fn(response)

    async def close(self):
        pass

    def queue_response(self, data: bytes):
        """Queue a response to be delivered after the next send."""
        self.responses.append(data)

    def inject_response(self, data: bytes):
        """Immediately inject a response (simulates unsolicited data)."""
        if self.recv_fn:
            self.recv_fn(data)


@pytest.fixture
def mock_transport():
    """Provide a fresh MockTransport instance."""
    return MockTransport()


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
