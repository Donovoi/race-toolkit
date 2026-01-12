import asyncio
import logging
import time
from typing import Callable

from librace.constants import RaceType
from librace.transport import Transport

from librace.packets import RaceHeader, RacePacket


class RACE:
    """This class implements the RACE protocol via a given Transport. It receives full packets and parses the header. Parsing the packet data is the responsibility of the user."""

    def __init__(self, transport: Transport, send_delay: float):
        self.transport = transport
        self.full_payload = b""
        self.sync_payload = b""
        self.expected_length = None
        self.recv_cb = None
        self.stop_event = asyncio.Event()
        self.send_delay = send_delay
        self.last_rx_time = None
        self.last_rx_type = None
        self.last_rx_id = None

    async def send(self, race_packet: RacePacket):
        if self.send_delay > 0:
            await asyncio.sleep(self.send_delay)
        await self.transport.send(race_packet.pack())

    async def send_sync(self, race_packet: RacePacket, timeout: float = 10.0):
        """Send a packet and wait for a response with timeout.

        Args:
            race_packet: The RACE packet to send.
            timeout: Maximum time to wait for response in seconds (default 10s).

        Returns:
            The response payload bytes.

        Raises:
            asyncio.TimeoutError: If no response is received within timeout.
        """
        if self.send_delay > 0:
            await asyncio.sleep(self.send_delay)
        await self.transport.send(race_packet.pack())
        logging.debug(
            "RACE send: id=0x%04X type=0x%02X len=0x%04X",
            race_packet.header.id,
            race_packet.header.type,
            race_packet.header.length,
        )
        send_start = time.monotonic()
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            detail = (
                "No inbound RACE notifications observed."
                if self.last_rx_time is None or self.last_rx_time < send_start
                else (
                    "Received non-response RACE packets (last type=0x%02X, id=0x%04X)."
                    % (
                        self.last_rx_type or -1,
                        self.last_rx_id or 0,
                    )
                )
            )
            raise asyncio.TimeoutError(
                f"No response received within {timeout}s. {detail} "
                "Likely causes: pairing/encryption required, device blocks RACE over BLE, "
                "or address is not the active endpoint."
            )
        self.stop_event.clear()
        r = self.sync_payload
        return r

    async def setup(self, recv_cb: Callable = None):
        self.recv_cb = recv_cb
        await self.transport.setup(self._recv)

    async def close(self):
        await self.transport.close()

    def reset(self):
        self.recv_cb = None
        self.expected_length = None
        self.full_payload = b""
        self.sync_payload = b""
        self.stop_event = asyncio.Event()

    def _recv(self, data: bytes):
        if self.expected_length is None:
            self.full_payload += data

            # we already received some data, but until now not enough to fully parse the RACE header, maybe now?
            if len(self.full_payload) >= RaceHeader.SIZE:
                data = self.full_payload

            if len(data) > RaceHeader.SIZE:
                # First fragment, parse the RaceHeader
                race_header = RaceHeader.unpack(data[: RaceHeader.SIZE])
                self.expected_length = race_header.length
                self.full_payload = data
            else:
                return
        else:
            # Continuation, we expact raw payload only. No RaceHeader.
            self.full_payload += data

        # Have we gotten all the continuation data?
        if len(self.full_payload) - 4 >= self.expected_length:
            race_header = RaceHeader.unpack(
                self.full_payload[: RaceHeader.SIZE]
            )
            try:
                type_name = RaceType(race_header.type).name
            except ValueError:
                type_name = "UNKNOWN"
            self.last_rx_time = time.monotonic()
            self.last_rx_type = race_header.type
            self.last_rx_id = race_header.id
            logging.debug(
                "RACE recv: id=0x%04X type=0x%02X(%s) len=0x%04X total=%d",
                race_header.id,
                race_header.type,
                type_name,
                race_header.length,
                len(self.full_payload),
            )

            if self.recv_cb:
                self.recv_cb(self.full_payload)

            self.sync_payload = self.full_payload
            # only stop blocking once we got the actual reponse, not the response indication
            if race_header.type == RaceType.RESPONSE:
                self.stop_event.set()
            else:
                logging.debug(
                    "RACE recv: non-response packet (type=0x%02X), waiting for RESPONSE",
                    race_header.type,
                )

            self.full_payload = b""
            self.expected_length = None
