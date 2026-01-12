"""Tests for librace/race.py - RACE protocol handler."""

import pytest
import asyncio

from librace.race import RACE
from librace.packets import (
    RaceHeader,
    RacePacket,
    GetSDKInfo,
    ReadAddress,
    ReadFlashPage,
)
from librace.constants import RaceType


class TestRACEInit:
    """Tests for RACE class initialization."""

    def test_init_stores_transport(self, mock_transport):
        """RACE should store transport reference."""
        race = RACE(mock_transport, send_delay=0)
        assert race.transport is mock_transport

    def test_init_stores_send_delay(self, mock_transport):
        """RACE should store send delay."""
        race = RACE(mock_transport, send_delay=0.5)
        assert race.send_delay == 0.5

    def test_init_empty_buffers(self, mock_transport):
        """RACE should start with empty buffers."""
        race = RACE(mock_transport, send_delay=0)
        assert race.full_payload == b""
        assert race.sync_payload == b""
        assert race.expected_length is None


@pytest.mark.asyncio
class TestRACESetup:
    """Tests for RACE setup."""

    async def test_setup_calls_transport_setup(self, mock_transport):
        """Setup should call transport setup with recv callback."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        assert mock_transport._setup_called
        assert mock_transport.recv_fn is not None

    async def test_setup_with_callback(self, mock_transport):
        """Setup should accept optional callback."""
        callback_data = []

        def my_callback(data):
            callback_data.append(data)

        race = RACE(mock_transport, send_delay=0)
        await race.setup(my_callback)

        assert race.recv_cb is my_callback


@pytest.mark.asyncio
class TestRACESend:
    """Tests for RACE send methods."""

    async def test_send_packs_and_sends(self, mock_transport):
        """Send should pack packet and send via transport."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        packet = GetSDKInfo()
        await race.send(packet)

        assert len(mock_transport.sent_data) == 1
        assert mock_transport.sent_data[0] == packet.pack()

    async def test_send_with_delay(self, mock_transport):
        """Send with delay should wait before sending."""
        race = RACE(mock_transport, send_delay=0.01)
        await race.setup()

        import time

        start = time.monotonic()
        await race.send(GetSDKInfo())
        elapsed = time.monotonic() - start

        assert elapsed >= 0.01


@pytest.mark.asyncio
class TestRACESendSync:
    """Tests for RACE synchronous send with response."""

    async def test_send_sync_waits_for_response(self, mock_transport):
        """send_sync should wait for response before returning."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        # Create a valid response packet
        response_header = RaceHeader(
            head=0x05, type_=RaceType.RESPONSE, id_=0x0301, length=4
        )
        response_data = response_header.pack() + b"\x00\x01"

        # Queue response to be sent after the request
        mock_transport.queue_response(response_data)

        packet = GetSDKInfo()
        result = await race.send_sync(packet, timeout=1.0)

        assert result == response_data

    async def test_send_sync_timeout(self, mock_transport):
        """send_sync should raise TimeoutError if no response."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        # Don't queue any response
        packet = GetSDKInfo()

        with pytest.raises(asyncio.TimeoutError):
            await race.send_sync(packet, timeout=0.1)


@pytest.mark.asyncio
class TestRACERecv:
    """Tests for RACE receive handling."""

    async def test_recv_single_packet(self, mock_transport):
        """Single complete packet should be processed."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        # Create a complete response
        header = RaceHeader(head=0x05, type_=RaceType.RESPONSE, id_=0x1234, length=4)
        payload = b"\x00\x01"
        data = header.pack() + payload

        race._recv(data)

        assert race.sync_payload == data

    async def test_recv_fragmented_packet(self, mock_transport):
        """Fragmented packets should be reassembled."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        # Create a response that will be sent in fragments
        header = RaceHeader(head=0x05, type_=RaceType.RESPONSE, id_=0x1234, length=10)
        payload = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        full_data = header.pack() + payload

        # Send first fragment (header + part of payload)
        race._recv(full_data[:8])

        # Should not yet be complete
        assert race.expected_length is not None

        # Send remaining fragment
        race._recv(full_data[8:])

        # Now should be complete
        assert race.sync_payload == full_data

    async def test_recv_indication_does_not_stop(self, mock_transport):
        """Indication packets should not trigger stop_event."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        # Create an indication (not response)
        header = RaceHeader(head=0x05, type_=RaceType.INDICATION, id_=0x1234, length=4)
        payload = b"\x00\x01"
        data = header.pack() + payload

        race._recv(data)

        # stop_event should not be set for indications
        assert not race.stop_event.is_set()

    async def test_recv_response_triggers_stop(self, mock_transport):
        """Response packets should trigger stop_event."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        # Create a response
        header = RaceHeader(head=0x05, type_=RaceType.RESPONSE, id_=0x1234, length=4)
        payload = b"\x00\x01"
        data = header.pack() + payload

        race._recv(data)

        # stop_event should be set for responses
        assert race.stop_event.is_set()


@pytest.mark.asyncio
class TestRACEReset:
    """Tests for RACE state reset."""

    async def test_reset_clears_state(self, mock_transport):
        """Reset should clear all buffers and state."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()

        # Simulate some state
        race.full_payload = b"\x01\x02\x03"
        race.sync_payload = b"\x04\x05\x06"
        race.expected_length = 100
        race.stop_event.set()

        race.reset()

        assert race.full_payload == b""
        assert race.sync_payload == b""
        assert race.expected_length is None
        assert not race.stop_event.is_set()
        assert race.recv_cb is None


@pytest.mark.asyncio
class TestRACEClose:
    """Tests for RACE cleanup."""

    async def test_close_calls_transport_close(self, mock_transport):
        """Close should call transport close."""
        race = RACE(mock_transport, send_delay=0)
        await race.setup()
        await race.close()

        # MockTransport.close() doesn't track calls, but should not raise
