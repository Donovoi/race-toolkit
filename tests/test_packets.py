"""Tests for librace/packets.py - RACE packet serialization/deserialization."""

import pytest
import struct

from librace.packets import (
    RaceHeader,
    RacePacket,
    ReadFlashPage,
    ReadFlashPageResponse,
    ReadAddress,
    ReadAddressResponse,
    GetEDRAddress,
    GetEDRAddressResponse,
    GetSDKInfo,
    BuildVersion,
    GetLinkKey,
    GetLinkKeyResponse,
    WriteFlashPage,
    WriteFlashPageResponse,
    ErasePartition,
    ErasePartitionReponse,
    FotaPartitionInfoQuery,
    FotaPartitionInfoQueryResponse,
    FotaStart,
    FotaStartResponse,
    FotaStop,
    FotaStopResponse,
    FotaStartTransaction,
    FotaStartTransactionResponse,
    FotaWriteState,
    FotaWriteStateResponse,
    FotaIntegrityCheck,
    FotaIntegrityCheckResponse,
    FotaCommit,
    FotaCommitResponse,
    ReturnCodeResponse,
)
from librace.constants import RaceId, RaceType


class TestRaceHeader:
    """Tests for RaceHeader pack/unpack."""

    def test_header_size(self):
        """Header should be exactly 6 bytes."""
        assert RaceHeader.SIZE == 6

    def test_header_pack_format(self):
        """Header format should be little-endian: head(1) + type(1) + length(2) + id(2)."""
        header = RaceHeader(head=0x05, type_=0x5A, id_=0x1234, length=0x0010)
        packed = header.pack()
        assert len(packed) == 6
        # Verify byte-by-byte
        assert packed[0] == 0x05  # head
        assert packed[1] == 0x5A  # type
        assert packed[2:4] == struct.pack("<H", 0x0010)  # length (little-endian)
        assert packed[4:6] == struct.pack("<H", 0x1234)  # id (little-endian)

    def test_header_roundtrip(self):
        """Pack then unpack should produce identical header."""
        original = RaceHeader(head=0x05, type_=0x5A, id_=0x1234, length=0x0010)
        packed = original.pack()
        unpacked = RaceHeader.unpack(packed)

        assert unpacked.head == original.head
        assert unpacked.type == original.type
        assert unpacked.length == original.length
        assert unpacked.id == original.id

    def test_header_unpack_short_data(self):
        """Unpack should raise ValueError if data is too short."""
        with pytest.raises(ValueError, match="Data too short"):
            RaceHeader.unpack(b"\x05\x5a\x10")  # Only 3 bytes, need 6

    def test_header_str(self):
        """Header string representation should include all fields."""
        header = RaceHeader(head=0x05, type_=0x5A, id_=0x1234, length=0x10)
        s = str(header)
        assert "head: 5" in s
        assert "type:" in s
        assert "length:" in s
        assert "id:" in s


class TestRacePacket:
    """Tests for base RacePacket class."""

    def test_packet_auto_length(self):
        """Packet should auto-calculate length field (payload + 2 for cmd ID)."""
        header = RaceHeader(head=0x05, type_=0x5A, id_=0x1234, length=0)
        payload = b"\x01\x02\x03\x04"
        packet = RacePacket(header, payload)

        # Length should be payload length + 2 (for cmd ID field)
        assert packet.header.length == len(payload) + 2

    def test_packet_pack(self):
        """Packet pack should concatenate header and payload."""
        header = RaceHeader(head=0x05, type_=0x5A, id_=0x1234, length=0)
        payload = b"\xaa\xbb\xcc\xdd"
        packet = RacePacket(header, payload)
        packed = packet.pack()

        assert len(packed) == RaceHeader.SIZE + len(payload)
        assert packed[: RaceHeader.SIZE] == packet.header.pack()
        assert packed[RaceHeader.SIZE :] == payload

    def test_packet_unpack(self):
        """Unpack should correctly split header and payload."""
        header = RaceHeader(head=0x05, type_=0x5A, id_=0x1234, length=6)
        payload = b"\x01\x02\x03\x04"
        data = header.pack() + payload

        unpacked = RacePacket.unpack(data)
        assert unpacked.header.id == 0x1234
        assert unpacked.payload == payload


class TestReadFlashPage:
    """Tests for flash memory read packet."""

    def test_read_flash_page_creation(self):
        """ReadFlashPage should have correct structure."""
        address = 0x08000000
        packet = ReadFlashPage(address, size=0x100)

        assert packet.header.head == 0x05
        assert packet.header.type == RaceType.CMD_EXPECTS_RESPONSE
        assert packet.header.id == RaceId.RACE_STORAGE_PAGE_READ

    def test_read_flash_page_payload(self):
        """ReadFlashPage payload should contain storage_type, size, and address."""
        address = 0x08001000
        size = 0x100
        storage_type = 0

        packet = ReadFlashPage(address, size=size, storage_type=storage_type)
        packed = packet.pack()

        # Payload starts after 6-byte header
        payload = packed[RaceHeader.SIZE :]
        assert payload[0] == storage_type
        assert payload[1] == (size >> 8)  # Size high byte
        # Address is 4 bytes little-endian starting at offset 2
        parsed_addr = struct.unpack("<I", payload[2:6])[0]
        assert parsed_addr == address


class TestReadFlashPageResponse:
    """Tests for flash read response parsing."""

    def test_response_unpack(self):
        """Response should correctly parse return code, address, and data."""
        # Build a response packet manually
        return_code = 0
        storage_type = 0
        page_address = 0x08000000
        page_data = bytes(range(256))  # 256 bytes of test data

        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_STORAGE_PAGE_READ,
            length=len(page_data) + ReadFlashPageResponse.PREAMBLE_SIZE + 2,
        )
        preamble = struct.pack(
            ReadFlashPageResponse.PREAMBLE_FORMAT,
            return_code,
            storage_type,
            0,
            0,
            page_address,
        )
        data = header.pack() + preamble + page_data

        response = ReadFlashPageResponse.unpack(data)
        assert response.return_code == return_code
        assert response.storage_type == storage_type
        assert response.page_address == page_address
        assert response.page_data == page_data


class TestReadAddress:
    """Tests for RAM address read packet."""

    def test_read_address_creation(self):
        """ReadAddress should target correct RACE command."""
        address = 0x10000000
        packet = ReadAddress(address)

        assert packet.header.id == RaceId.RACE_READ_ADDRESS
        assert packet.header.type == RaceType.CMD_EXPECTS_RESPONSE

    def test_read_address_payload(self):
        """ReadAddress payload should contain address in little-endian."""
        address = 0xDEADBEEF
        packet = ReadAddress(address)
        packed = packet.pack()

        payload = packed[RaceHeader.SIZE :]
        # First 2 bytes are padding (0x00, 0x00)
        assert payload[0:2] == b"\x00\x00"
        # Next 4 bytes are the address
        parsed_addr = struct.unpack("<I", payload[2:6])[0]
        assert parsed_addr == address


class TestReadAddressResponse:
    """Tests for RAM read response parsing."""

    def test_response_unpack(self):
        """Response should correctly parse return code, address, and data."""
        return_code = 0
        page_address = 0x10000000
        page_data = b"\xaa\xbb\xcc\xdd"

        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_READ_ADDRESS,
            length=len(page_data) + ReadAddressResponse.PREAMBLE_SIZE + 2,
        )
        preamble = struct.pack(
            ReadAddressResponse.PREAMBLE_FORMAT, return_code, 0, page_address
        )
        data = header.pack() + preamble + page_data

        response = ReadAddressResponse.unpack(data)
        assert response.return_code == return_code
        assert response.page_address == page_address
        assert response.page_data == page_data


class TestGetEDRAddress:
    """Tests for Bluetooth address retrieval packet."""

    def test_get_edr_address_creation(self):
        """GetEDRAddress should be a simple command with no payload."""
        packet = GetEDRAddress()

        assert packet.header.id == RaceId.RACE_GET_BD_ADDRESS
        assert packet.header.type == RaceType.CMD_EXPECTS_RESPONSE
        assert packet.payload == b""


class TestGetEDRAddressResponse:
    """Tests for Bluetooth address response parsing."""

    def test_response_unpack(self):
        """Response should extract BD address with byte reversal."""
        return_code = 0
        # BD address bytes (will be reversed in response)
        bd_addr_bytes = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_GET_BD_ADDRESS,
            length=len(bd_addr_bytes) + GetEDRAddressResponse.PREAMBLE_SIZE + 2,
        )
        preamble = struct.pack(GetEDRAddressResponse.PREAMBLE_FORMAT, return_code, 0)
        data = header.pack() + preamble + bd_addr_bytes

        response = GetEDRAddressResponse.unpack(data)
        assert response.return_code == return_code
        # BD address should be reversed
        assert response.bd_addr == bd_addr_bytes[::-1]


class TestGetLinkKey:
    """Tests for link key retrieval packet."""

    def test_get_link_key_creation(self):
        """GetLinkKey should be a simple command."""
        packet = GetLinkKey()
        assert packet.header.id == RaceId.RACE_GET_LINK_KEY


class TestGetLinkKeyResponse:
    """Tests for link key response parsing."""

    def test_response_with_no_devices(self):
        """Response with 0 devices should have empty link_keys list."""
        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_GET_LINK_KEY,
            length=GetLinkKeyResponse.PREAMBLE_SIZE + 2,
        )
        preamble = struct.pack(GetLinkKeyResponse.PREAMBLE_FORMAT, 0, 0, 0)
        data = header.pack() + preamble

        response = GetLinkKeyResponse.unpack(data)
        assert response.num_of_devices == 0
        assert response.link_keys == []

    def test_response_with_one_device(self):
        """Response should correctly parse link key for one device."""
        num_devices = 1
        link_key = bytes(range(16))  # 16-byte link key

        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_GET_LINK_KEY,
            length=GetLinkKeyResponse.PREAMBLE_SIZE + (6 + 16 + 1) * num_devices + 2,
        )
        preamble = struct.pack(GetLinkKeyResponse.PREAMBLE_FORMAT, 0, num_devices, 0)
        # Record: 6 bytes addr (zeros) + 16 bytes key
        record = bytes([0] * 6) + link_key
        data = header.pack() + preamble + record

        response = GetLinkKeyResponse.unpack(data)
        assert response.num_of_devices == num_devices
        assert len(response.link_keys) == 1
        assert response.link_keys[0] == link_key


class TestGetSDKInfo:
    """Tests for SDK info packet."""

    def test_sdk_info_creation(self):
        """GetSDKInfo should target correct command."""
        packet = GetSDKInfo()
        assert packet.header.id == RaceId.RACE_READ_SDK_VERSION


class TestBuildVersion:
    """Tests for build version packet."""

    def test_build_version_creation(self):
        """BuildVersion should target correct command."""
        packet = BuildVersion()
        assert packet.header.id == RaceId.RACE_GET_BUILD_VERSION


class TestFotaPackets:
    """Tests for FOTA-related packets."""

    def test_fota_partition_info_query(self):
        """FotaPartitionInfoQuery should have correct structure."""
        packet = FotaPartitionInfoQuery()
        assert packet.header.id == RaceId.RACE_FOTA_PARTITION_INFO_QUERY
        assert packet.payload == b"\x00"

    def test_fota_partition_info_response(self):
        """Response should parse start address and length."""
        return_code = 0
        start_addr = 0x08100000
        length = 0x00100000

        header = RaceHeader(
            head=0x05,
            type_=RaceType.RESPONSE,
            id_=RaceId.RACE_FOTA_PARTITION_INFO_QUERY,
            length=FotaPartitionInfoQueryResponse.PREAMBLE_SIZE + 2,
        )
        preamble = struct.pack(
            FotaPartitionInfoQueryResponse.PREAMBLE_FORMAT,
            return_code,
            0,
            start_addr,
            length,
        )
        data = header.pack() + preamble

        response = FotaPartitionInfoQueryResponse.unpack(data)
        assert response.return_code == return_code
        assert response.start_addr == start_addr
        assert response.length == length

    def test_fota_start(self):
        """FotaStart should have correct ID and payload."""
        packet = FotaStart()
        assert packet.header.id == RaceId.RACE_FOTA_START
        assert packet.payload == b"\x01\x00"

    def test_fota_stop(self):
        """FotaStop should have correct ID."""
        packet = FotaStop()
        assert packet.header.id == RaceId.RACE_FOTA_STOP

    def test_fota_start_transaction(self):
        """FotaStartTransaction should have correct ID."""
        packet = FotaStartTransaction()
        assert packet.header.id == RaceId.RACE_FOTA_START_TRANSCATION

    def test_fota_write_state(self):
        """FotaWriteState should accept custom state."""
        packet = FotaWriteState(state=b"\x02\x03")
        assert packet.header.id == RaceId.RACE_FOTA_WRITE_STATE
        assert packet.payload == b"\x02\x03"

    def test_fota_integrity_check(self):
        """FotaIntegrityCheck should have correct structure."""
        packet = FotaIntegrityCheck()
        assert packet.header.id == RaceId.RACE_FOTA_INTEGRITY_CHECK

    def test_fota_commit(self):
        """FotaCommit should have correct structure."""
        packet = FotaCommit()
        assert packet.header.id == RaceId.RACE_FOTA_COMMIT


class TestWriteFlashPage:
    """Tests for flash write packet."""

    def test_write_flash_single_page(self):
        """WriteFlashPage should correctly structure single page write."""
        address = 0x08000000
        data = bytes([0xAA] * 0x100)  # One page of data

        packet = WriteFlashPage(address, data, storage_type=0)
        assert packet.header.id == RaceId.RACE_STORAGE_PAGE_PROGRAM
        assert packet.header.head == 0x15  # Different head for write


class TestErasePartition:
    """Tests for partition erase packet."""

    def test_erase_partition_creation(self):
        """ErasePartition should contain address and length."""
        address = 0x08100000
        length = 0x10000

        packet = ErasePartition(address, length, storage_type=0)
        assert packet.header.id == RaceId.RACE_STORAGE_PARTITION_ERASE

        # Verify payload contains correct data
        packed = packet.pack()
        payload = packed[RaceHeader.SIZE :]
        storage_type, parsed_length, parsed_addr = struct.unpack("<BII", payload[:9])
        assert storage_type == 0
        assert parsed_length == length
        assert parsed_addr == address
