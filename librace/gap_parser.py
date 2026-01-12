"""Generic Access Profile (GAP) Advertisement Data Parser.

This module provides utilities for parsing BLE advertisement data according to
the Bluetooth Core Specification. It can decode various GAP AD types including:

- Service UUIDs (16-bit, 32-bit, 128-bit)
- Local Name (shortened and complete)
- Manufacturer Specific Data
- Service Data
- Tx Power Level
- Appearance
- Flags

Reference: Bluetooth Core Specification, Vol. 3, Part C, Section 8 (Advertising Data)
"""

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import IntEnum

from librace.ble_tables import (
    GAP_AD_TYPES,
    lookup_uuid16,
    APPLE_CONTINUITY_TYPES,
)
from librace.manufacturer_ids import lookup_manufacturer, parse_manufacturer_data


class GapAdType(IntEnum):
    """GAP Advertising Data Type codes."""

    FLAGS = 0x01
    INCOMPLETE_16BIT_UUIDS = 0x02
    COMPLETE_16BIT_UUIDS = 0x03
    INCOMPLETE_32BIT_UUIDS = 0x04
    COMPLETE_32BIT_UUIDS = 0x05
    INCOMPLETE_128BIT_UUIDS = 0x06
    COMPLETE_128BIT_UUIDS = 0x07
    SHORTENED_LOCAL_NAME = 0x08
    COMPLETE_LOCAL_NAME = 0x09
    TX_POWER_LEVEL = 0x0A
    CLASS_OF_DEVICE = 0x0D
    SIMPLE_PAIRING_HASH_C192 = 0x0E
    SIMPLE_PAIRING_RANDOMIZER_R192 = 0x0F
    DEVICE_ID = 0x10
    SECURITY_MANAGER_OOB_FLAGS = 0x11
    SLAVE_CONNECTION_INTERVAL_RANGE = 0x12
    SERVICE_SOLICITATION_16BIT = 0x14
    SERVICE_SOLICITATION_128BIT = 0x15
    SERVICE_DATA_16BIT = 0x16
    PUBLIC_TARGET_ADDRESS = 0x17
    RANDOM_TARGET_ADDRESS = 0x18
    APPEARANCE = 0x19
    ADVERTISING_INTERVAL = 0x1A
    LE_BLUETOOTH_DEVICE_ADDRESS = 0x1B
    LE_ROLE = 0x1C
    SIMPLE_PAIRING_HASH_C256 = 0x1D
    SIMPLE_PAIRING_RANDOMIZER_R256 = 0x1E
    SERVICE_SOLICITATION_32BIT = 0x1F
    SERVICE_DATA_32BIT = 0x20
    SERVICE_DATA_128BIT = 0x21
    LE_SECURE_CONNECTIONS_CONFIRMATION = 0x22
    LE_SECURE_CONNECTIONS_RANDOM = 0x23
    URI = 0x24
    INDOOR_POSITIONING = 0x25
    TRANSPORT_DISCOVERY_DATA = 0x26
    LE_SUPPORTED_FEATURES = 0x27
    CHANNEL_MAP_UPDATE = 0x28
    PB_ADV = 0x29
    MESH_MESSAGE = 0x2A
    MESH_BEACON = 0x2B
    BIG_INFO = 0x2C
    BROADCAST_CODE = 0x2D
    RESOLVABLE_SET_IDENTIFIER = 0x2E
    ADVERTISING_INTERVAL_LONG = 0x2F
    BROADCAST_NAME = 0x30
    THREE_D_INFORMATION = 0x3D
    MANUFACTURER_SPECIFIC = 0xFF


@dataclass
class GapField:
    """Represents a single GAP advertisement data field."""

    ad_type: int
    type_name: str
    raw_data: bytes
    value: Any = None
    offset: int = 0
    length: int = 0

    def __repr__(self) -> str:
        if self.value is not None:
            return f"GapField({self.type_name}: {self.value})"
        return f"GapField({self.type_name}: {self.raw_data.hex()})"


@dataclass
class ParsedAdvertisement:
    """Container for parsed BLE advertisement data."""

    fields: List[GapField] = field(default_factory=list)
    local_name: Optional[str] = None
    tx_power: Optional[int] = None
    appearance: Optional[int] = None
    flags: Optional[int] = None
    service_uuids: List[str] = field(default_factory=list)
    service_data: Dict[str, bytes] = field(default_factory=dict)
    manufacturer_data: Optional[Tuple[Optional[str], bytes]] = None
    company_code: Optional[str] = None
    company_name: Optional[str] = None

    def get_gap_types(self) -> List[str]:
        """Get list of all GAP type names present in the advertisement."""
        return [f.type_name for f in self.fields]

    def has_unknown_services(self) -> bool:
        """Check if any service UUIDs are unknown/unregistered."""
        for uuid in self.service_uuids:
            if len(uuid) == 4 and lookup_uuid16(uuid) is None:
                return True
        return False


class GapParser:
    """Parser for BLE Generic Access Profile advertisement data."""

    @staticmethod
    def parse_buffer(data: bytes) -> List[GapField]:
        """Parse raw advertisement data into a list of GapField objects.

        Args:
            data: Raw advertisement data bytes

        Returns:
            List of GapField objects representing each AD structure
        """
        fields = []
        offset = 0

        while offset < len(data):
            # Check if we have at least 1 byte for length
            if offset >= len(data):
                break

            field_length = data[offset]

            # Length of 0 means end of data
            if field_length == 0:
                break

            # Check if we have enough data
            if offset + 1 + field_length > len(data):
                break

            ad_type = data[offset + 1]
            ad_data = data[offset + 2 : offset + 1 + field_length]

            # Get type name
            type_info = GAP_AD_TYPES.get(ad_type)
            if type_info is not None:
                if isinstance(type_info, tuple):
                    type_name = type_info[0]
                else:
                    type_name = str(type_info)
            else:
                type_name = f"Unknown(0x{ad_type:02x})"

            gap_field = GapField(
                ad_type=ad_type,
                type_name=type_name,
                raw_data=ad_data,
                offset=offset,
                length=field_length,
            )

            # Parse the value based on type
            gap_field.value = GapParser._decode_field(ad_type, ad_data)

            fields.append(gap_field)
            offset += 1 + field_length

        return fields

    @staticmethod
    def _decode_field(ad_type: int, data: bytes) -> Any:
        """Decode a GAP field value based on its type.

        Args:
            ad_type: The AD type code
            data: The field data bytes

        Returns:
            Decoded value (type depends on AD type)
        """
        if ad_type == GapAdType.FLAGS:
            return data[0] if len(data) >= 1 else None

        elif ad_type in (GapAdType.SHORTENED_LOCAL_NAME, GapAdType.COMPLETE_LOCAL_NAME):
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.decode("latin-1", errors="replace")

        elif ad_type == GapAdType.TX_POWER_LEVEL:
            if len(data) >= 1:
                return struct.unpack("b", data[:1])[0]  # Signed byte
            return None

        elif ad_type == GapAdType.APPEARANCE:
            if len(data) >= 2:
                return struct.unpack("<H", data[:2])[0]
            return None

        elif ad_type in (
            GapAdType.INCOMPLETE_16BIT_UUIDS,
            GapAdType.COMPLETE_16BIT_UUIDS,
            GapAdType.SERVICE_SOLICITATION_16BIT,
        ):
            return GapParser._decode_uuid_list(data, 2)

        elif ad_type in (
            GapAdType.INCOMPLETE_32BIT_UUIDS,
            GapAdType.COMPLETE_32BIT_UUIDS,
            GapAdType.SERVICE_SOLICITATION_32BIT,
        ):
            return GapParser._decode_uuid_list(data, 4)

        elif ad_type in (
            GapAdType.INCOMPLETE_128BIT_UUIDS,
            GapAdType.COMPLETE_128BIT_UUIDS,
            GapAdType.SERVICE_SOLICITATION_128BIT,
        ):
            return GapParser._decode_uuid_list(data, 16)

        elif ad_type == GapAdType.SERVICE_DATA_16BIT:
            return GapParser._decode_service_data(data, 2)

        elif ad_type == GapAdType.SERVICE_DATA_32BIT:
            return GapParser._decode_service_data(data, 4)

        elif ad_type == GapAdType.SERVICE_DATA_128BIT:
            return GapParser._decode_service_data(data, 16)

        elif ad_type == GapAdType.MANUFACTURER_SPECIFIC:
            return GapParser._decode_manufacturer_data(data)

        elif ad_type == GapAdType.URI:
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.hex()

        elif ad_type == GapAdType.BROADCAST_NAME:
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.hex()

        # Default: return as hex string
        return data.hex()

    @staticmethod
    def _decode_uuid_list(data: bytes, byte_size: int) -> List[str]:
        """Decode a list of UUIDs from raw bytes.

        Args:
            data: Raw bytes containing UUIDs
            byte_size: Size of each UUID in bytes (2, 4, or 16)

        Returns:
            List of UUID strings in hex format
        """
        uuids = []
        offset = 0

        while offset + byte_size <= len(data):
            uuid_bytes = data[offset : offset + byte_size]
            # UUIDs are stored in little-endian, reverse for display
            uuid_hex = uuid_bytes[::-1].hex()
            uuids.append(uuid_hex)
            offset += byte_size

        return uuids

    @staticmethod
    def _decode_service_data(data: bytes, uuid_size: int) -> Dict[str, bytes]:
        """Decode service data (UUID + payload).

        Args:
            data: Raw bytes containing UUID and payload
            uuid_size: Size of UUID in bytes (2, 4, or 16)

        Returns:
            Dict mapping UUID string to payload bytes
        """
        if len(data) < uuid_size:
            return {}

        uuid_bytes = data[:uuid_size]
        uuid_hex = uuid_bytes[::-1].hex()  # Little-endian to hex
        payload = data[uuid_size:]

        return {uuid_hex: payload}

    @staticmethod
    def _decode_manufacturer_data(data: bytes) -> Dict[str, Any]:
        """Decode manufacturer-specific data.

        Args:
            data: Raw manufacturer data bytes

        Returns:
            Dict with company_code, company_name, and payload
        """
        if len(data) < 2:
            return {"raw": data.hex()}

        # Company ID is little-endian 16-bit value
        company_id = struct.unpack("<H", data[:2])[0]
        company_code = f"{company_id:04x}"
        company_name = lookup_manufacturer(company_code)
        payload = data[2:]

        result = {
            "company_code": company_code,
            "company_name": company_name,
            "payload": payload,
            "payload_hex": payload.hex(),
        }

        # Special handling for Apple (0x004c)
        if company_code == "004c" and len(payload) >= 2:
            apple_type = f"{payload[0]:02x}"
            apple_type_name = APPLE_CONTINUITY_TYPES.get(apple_type)
            if apple_type_name:
                result["apple_type"] = apple_type
                result["apple_type_name"] = apple_type_name

        return result

    @staticmethod
    def parse(data: Union[bytes, str]) -> ParsedAdvertisement:
        """Parse advertisement data and return a structured result.

        Args:
            data: Raw advertisement data as bytes or base64 string

        Returns:
            ParsedAdvertisement with all decoded fields
        """
        import base64

        if isinstance(data, str):
            # Assume base64 encoded
            data = base64.b64decode(data)

        fields = GapParser.parse_buffer(data)
        result = ParsedAdvertisement(fields=fields)

        for gap_field in fields:
            if gap_field.ad_type == GapAdType.FLAGS:
                result.flags = gap_field.value

            elif gap_field.ad_type in (
                GapAdType.SHORTENED_LOCAL_NAME,
                GapAdType.COMPLETE_LOCAL_NAME,
            ):
                result.local_name = gap_field.value

            elif gap_field.ad_type == GapAdType.TX_POWER_LEVEL:
                result.tx_power = gap_field.value

            elif gap_field.ad_type == GapAdType.APPEARANCE:
                result.appearance = gap_field.value

            elif gap_field.ad_type in (
                GapAdType.INCOMPLETE_16BIT_UUIDS,
                GapAdType.COMPLETE_16BIT_UUIDS,
                GapAdType.INCOMPLETE_32BIT_UUIDS,
                GapAdType.COMPLETE_32BIT_UUIDS,
                GapAdType.INCOMPLETE_128BIT_UUIDS,
                GapAdType.COMPLETE_128BIT_UUIDS,
            ):
                if isinstance(gap_field.value, list):
                    # Add unique UUIDs
                    for uuid in gap_field.value:
                        if uuid not in result.service_uuids:
                            result.service_uuids.append(uuid)

            elif gap_field.ad_type in (
                GapAdType.SERVICE_DATA_16BIT,
                GapAdType.SERVICE_DATA_32BIT,
                GapAdType.SERVICE_DATA_128BIT,
            ):
                if isinstance(gap_field.value, dict):
                    result.service_data.update(gap_field.value)
                    # Also add the UUID to service_uuids
                    for uuid in gap_field.value.keys():
                        if uuid not in result.service_uuids:
                            result.service_uuids.append(uuid)

            elif gap_field.ad_type == GapAdType.MANUFACTURER_SPECIFIC:
                if isinstance(gap_field.value, dict):
                    result.company_code = gap_field.value.get("company_code")
                    result.company_name = gap_field.value.get("company_name")
                    payload = gap_field.value.get("payload", b"")
                    result.manufacturer_data = (result.company_name, payload)

        return result

    @staticmethod
    def get_service_uuids(fields: List[GapField]) -> List[str]:
        """Extract all service UUIDs from parsed fields.

        Args:
            fields: List of parsed GapField objects

        Returns:
            List of unique UUID strings
        """
        uuids = []

        for gap_field in fields:
            if gap_field.ad_type in (
                GapAdType.INCOMPLETE_16BIT_UUIDS,
                GapAdType.COMPLETE_16BIT_UUIDS,
                GapAdType.INCOMPLETE_32BIT_UUIDS,
                GapAdType.COMPLETE_32BIT_UUIDS,
                GapAdType.INCOMPLETE_128BIT_UUIDS,
                GapAdType.COMPLETE_128BIT_UUIDS,
            ):
                if isinstance(gap_field.value, list):
                    for uuid in gap_field.value:
                        if uuid not in uuids:
                            uuids.append(uuid)

            elif gap_field.ad_type in (
                GapAdType.SERVICE_DATA_16BIT,
                GapAdType.SERVICE_DATA_32BIT,
                GapAdType.SERVICE_DATA_128BIT,
            ):
                if isinstance(gap_field.value, dict):
                    for uuid in gap_field.value.keys():
                        if uuid not in uuids:
                            uuids.append(uuid)

        return uuids


def parse_advertisement(data: Union[bytes, str]) -> ParsedAdvertisement:
    """Convenience function to parse BLE advertisement data.

    Args:
        data: Raw advertisement data as bytes or base64 string

    Returns:
        ParsedAdvertisement with all decoded fields

    Example:
        >>> adv = parse_advertisement(bytes.fromhex("0201060909536f6e79205742"))
        >>> print(adv.local_name)
        'Sony WB'
        >>> print(adv.flags)
        6
    """
    return GapParser.parse(data)


def decode_flags(flags: int) -> Dict[str, bool]:
    """Decode GAP Flags byte into individual flag values.

    Args:
        flags: The flags byte value

    Returns:
        Dict with flag names and their boolean values

    Flags:
        - le_limited_discoverable: LE Limited Discoverable Mode
        - le_general_discoverable: LE General Discoverable Mode
        - br_edr_not_supported: BR/EDR Not Supported
        - le_br_edr_controller: Simultaneous LE and BR/EDR (Controller)
        - le_br_edr_host: Simultaneous LE and BR/EDR (Host)
    """
    return {
        "le_limited_discoverable": bool(flags & 0x01),
        "le_general_discoverable": bool(flags & 0x02),
        "br_edr_not_supported": bool(flags & 0x04),
        "le_br_edr_controller": bool(flags & 0x08),
        "le_br_edr_host": bool(flags & 0x10),
    }
