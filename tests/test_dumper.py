"""Tests for librace/dumper.py - Memory/Flash dumping classes."""

import pytest
import asyncio
import io
import struct

from librace.dumper import RACEDumper, RACERAMDumper, RACEFlashDumper
from librace.race import RACE
from librace.packets import (
    RaceHeader,
    ReadFlashPageResponse,
    ReadAddressResponse,
)
from librace.constants import RaceId, RaceType


pytestmark = pytest.mark.asyncio


class TestRACERAMDumper:
    """Tests for RAM dumping functionality."""

    async def test_dumper_init(self, mock_transport):
        """Dumper should initialize with correct parameters."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACERAMDumper(race, start=0x10000000, size=0x100, progress=False)

        assert dumper.start == 0x10000000
        assert dumper.size == 0x100
        assert dumper.unit_size == 0x4  # RAM reads 4 bytes at a time
        assert dumper.desc == "RAM"

    async def test_dumper_sends_correct_packets(self, mock_transport):
        """Dumper should send ReadAddress packets for each word."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACERAMDumper(race, start=0x10000000, size=0x8, progress=False)

        # Queue responses for 2 words (8 bytes)
        for addr_offset in [0, 4]:
            header = RaceHeader(
                head=0x05,
                type_=RaceType.RESPONSE,
                id_=RaceId.RACE_READ_ADDRESS,
                length=ReadAddressResponse.PREAMBLE_SIZE + 4 + 2,
            )
            preamble = struct.pack(
                ReadAddressResponse.PREAMBLE_FORMAT, 0, 0, 0x10000000 + addr_offset
            )
            data = header.pack() + preamble + bytes([addr_offset] * 4)
            mock_transport.queue_response(data)

        result = await dumper.dump()

        # Should have sent 2 packets (one per word)
        assert len(mock_transport.sent_data) == 2
        # Result should be 8 bytes
        assert len(result) == 8

    async def test_dumper_unpack_handles_error(self, mock_transport):
        """Dumper should handle error responses gracefully."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACERAMDumper(race, start=0x10000000, size=0x4, progress=False)

        # Queue error response (return_code != 0)
        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_READ_ADDRESS,
            length=ReadAddressResponse.PREAMBLE_SIZE + 4 + 2,
        )
        preamble = struct.pack(
            ReadAddressResponse.PREAMBLE_FORMAT,
            1,
            0,
            0x10000000,  # return_code = 1 (error)
        )
        data = header.pack() + preamble + b"\x00\x00\x00\x00"
        mock_transport.queue_response(data)

        result = await dumper.dump()

        # Should have had_errors flag set
        assert dumper.had_errors is True


class TestRACEFlashDumper:
    """Tests for Flash dumping functionality."""

    async def test_dumper_init(self, mock_transport):
        """Flash dumper should initialize with correct parameters."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACEFlashDumper(race, start=0x08000000, size=0x200, progress=False)

        assert dumper.start == 0x08000000
        assert dumper.size == 0x200
        assert dumper.unit_size == 0x100  # Flash reads 256 bytes at a time
        assert dumper.desc == "Flash"

    async def test_dumper_sends_correct_packets(self, mock_transport):
        """Dumper should send ReadFlashPage packets for each page."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACEFlashDumper(race, start=0x08000000, size=0x200, progress=False)

        # Queue responses for 2 pages (0x200 bytes)
        for page_offset in [0, 0x100]:
            header = RaceHeader(
                head=0x05,
                type_=RaceType.RESPONSE,
                id_=RaceId.RACE_STORAGE_PAGE_READ,
                length=ReadFlashPageResponse.PREAMBLE_SIZE + 0x100 + 2,
            )
            preamble = struct.pack(
                ReadFlashPageResponse.PREAMBLE_FORMAT,
                0,  # return_code
                0,  # storage_type
                0,
                0,
                0x08000000 + page_offset,  # address
            )
            page_data = bytes([page_offset & 0xFF] * 0x100)
            data = header.pack() + preamble + page_data
            mock_transport.queue_response(data)

        result = await dumper.dump()

        # Should have sent 2 packets (one per page)
        assert len(mock_transport.sent_data) == 2
        # Result should be 0x200 bytes
        assert len(result) == 0x200

    async def test_dumper_writes_to_file(self, mock_transport, tmp_path):
        """Dumper should write data to file descriptor if provided."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACEFlashDumper(race, start=0x08000000, size=0x100, progress=False)

        # Queue one page response
        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_STORAGE_PAGE_READ,
            length=ReadFlashPageResponse.PREAMBLE_SIZE + 0x100 + 2,
        )
        preamble = struct.pack(
            ReadFlashPageResponse.PREAMBLE_FORMAT, 0, 0, 0, 0, 0x08000000
        )
        page_data = bytes(range(256))
        data = header.pack() + preamble + page_data
        mock_transport.queue_response(data)

        # Dump to file
        output_file = tmp_path / "flash.bin"
        with open(output_file, "wb") as f:
            await dumper.dump(fd=f)

        # Verify file contents
        with open(output_file, "rb") as f:
            file_data = f.read()

        assert file_data == page_data

    async def test_dumper_unpack_handles_error(self, mock_transport):
        """Flash dumper should handle error responses gracefully."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACEFlashDumper(race, start=0x08000000, size=0x100, progress=False)

        # Queue error response
        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_STORAGE_PAGE_READ,
            length=ReadFlashPageResponse.PREAMBLE_SIZE + 0x100 + 2,
        )
        preamble = struct.pack(
            ReadFlashPageResponse.PREAMBLE_FORMAT,
            1,  # return_code = 1 (error)
            0,
            0,
            0,
            0x08000000,
        )
        page_data = bytes([0] * 0x100)
        data = header.pack() + preamble + page_data
        mock_transport.queue_response(data)

        result = await dumper.dump()

        # Should have had_errors flag set
        assert dumper.had_errors is True

    async def test_dumper_timeout(self, mock_transport):
        """Dumper should raise TimeoutError if no response received."""
        race = RACE(mock_transport, send_delay=0)
        dumper = RACEFlashDumper(race, start=0x08000000, size=0x100, progress=False)
        dumper.response_timeout = 0.1  # Short timeout for test

        # Don't queue any response
        with pytest.raises(asyncio.TimeoutError):
            await dumper.dump()
