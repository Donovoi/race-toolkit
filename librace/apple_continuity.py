"""Apple Continuity Protocol Parser.

This module provides parsing capabilities for Apple's Continuity protocol,
which is used in BLE advertisements from Apple devices for various features:

- iBeacon: Location beacons
- AirDrop: Wireless file sharing
- HomeKit: Smart home accessories
- ProximityPairing: AirPods and other accessories pairing
- Handoff: Cross-device continuity
- NearbyInfo: Device presence and state
- NearbyAction: Actions like WiFi password sharing, Apple Pay
- FindMy: Device and item location tracking
- AirPlay: Media streaming

Reference: https://github.com/furiousMAC/continuity
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import IntEnum

from librace.ble_tables import (
    APPLE_CONTINUITY_TYPES,
    APPLE_NEARBY_INFO_ACTION_CODES,
    APPLE_NEARBY_ACTION_TYPES,
)


class AppleContinuityType(IntEnum):
    """Apple Continuity message type codes."""

    IBEACON = 0x02
    AIRPRINT = 0x03
    AIRDROP = 0x05
    HOMEKIT = 0x06
    PROXIMITY_PAIRING = 0x07
    SIRI = 0x08
    AIRPLAY_TARGET = 0x09
    AIRPLAY_SOURCE = 0x0A
    MAGIC_SWITCH = 0x0B
    HANDOFF = 0x0C
    TETHERING_TARGET = 0x0D
    TETHERING_SOURCE = 0x0E
    NEARBY_ACTION = 0x0F
    NEARBY_INFO = 0x10
    FINDMY = 0x12


@dataclass
class IBeaconData:
    """Parsed iBeacon advertisement data."""

    uuid: str
    major: int
    minor: int
    tx_power: int

    def __repr__(self) -> str:
        return f"iBeacon(uuid={self.uuid}, major={self.major}, minor={self.minor}, tx_power={self.tx_power})"


@dataclass
class NearbyInfoData:
    """Parsed NearbyInfo advertisement data."""

    action_code: int
    action: str
    flags: Dict[str, bool] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"NearbyInfo(action={self.action}, flags={self.flags})"


@dataclass
class NearbyActionData:
    """Parsed NearbyAction advertisement data."""

    action_type: int
    action_name: str
    flags: int

    def __repr__(self) -> str:
        return f"NearbyAction(action={self.action_name}, flags=0x{self.flags:02x})"


@dataclass
class FindMyData:
    """Parsed FindMy advertisement data."""

    maintained: bool

    def __repr__(self) -> str:
        return f"FindMy(maintained={self.maintained})"


@dataclass
class AirPlayData:
    """Parsed AirPlay advertisement data."""

    ip_address: Optional[str] = None

    def __repr__(self) -> str:
        return f"AirPlay(ip={self.ip_address})"


@dataclass
class AppleContinuityResult:
    """Container for parsed Apple Continuity protocol data."""

    type_code: str
    type_name: Optional[str]
    raw_data: bytes

    # Specific parsed data based on type
    ibeacon: Optional[IBeaconData] = None
    nearby_info: Optional[NearbyInfoData] = None
    nearby_action: Optional[NearbyActionData] = None
    findmy: Optional[FindMyData] = None
    airplay: Optional[AirPlayData] = None

    # Error info
    protocol_error: Optional[str] = None

    def __repr__(self) -> str:
        parts = [f"AppleContinuity(type={self.type_name or self.type_code}"]
        if self.ibeacon:
            parts.append(f", {self.ibeacon}")
        if self.nearby_info:
            parts.append(f", {self.nearby_info}")
        if self.nearby_action:
            parts.append(f", {self.nearby_action}")
        if self.findmy:
            parts.append(f", {self.findmy}")
        if self.airplay:
            parts.append(f", {self.airplay}")
        if self.protocol_error:
            parts.append(f", error={self.protocol_error}")
        parts.append(")")
        return "".join(parts)


class AppleContinuityParser:
    """Parser for Apple Continuity protocol in BLE manufacturer data."""

    # Apple's Bluetooth SIG company identifier
    APPLE_COMPANY_ID = 0x004C

    @staticmethod
    def is_apple_manufacturer_data(data: bytes) -> bool:
        """Check if manufacturer data is from Apple.

        Args:
            data: Raw manufacturer-specific data bytes

        Returns:
            True if the data starts with Apple's company ID (0x004C)
        """
        if len(data) < 2:
            return False

        # Company ID is little-endian
        company_id = int.from_bytes(data[:2], byteorder="little")
        return company_id == AppleContinuityParser.APPLE_COMPANY_ID

    @staticmethod
    def parse(manufacturer_data: bytes) -> AppleContinuityResult:
        """Parse Apple Continuity protocol from manufacturer data.

        Args:
            manufacturer_data: Raw manufacturer-specific data bytes
                              (should include the 2-byte company ID prefix)

        Returns:
            AppleContinuityResult with parsed protocol data

        Example:
            >>> data = bytes.fromhex("4c00021503..."))  # iBeacon
            >>> result = AppleContinuityParser.parse(data)
            >>> print(result.ibeacon.uuid)
        """
        if len(manufacturer_data) < 4:
            return AppleContinuityResult(
                type_code="",
                type_name=None,
                raw_data=manufacturer_data,
                protocol_error="Data too short for Apple Continuity",
            )

        # Skip company ID (first 2 bytes)
        sub_type = manufacturer_data[2]
        sub_type_len = manufacturer_data[3]
        sub_type_hex = f"{sub_type:02x}"

        type_name = APPLE_CONTINUITY_TYPES.get(sub_type_hex)

        result = AppleContinuityResult(
            type_code=sub_type_hex,
            type_name=type_name,
            raw_data=manufacturer_data,
        )

        # Validate message length
        if sub_type_len + 4 > len(manufacturer_data):
            result.protocol_error = (
                f"Incorrect message length: expected {sub_type_len} bytes, "
                f"but only {len(manufacturer_data) - 4} available"
            )
            # Continue parsing what we can

        # Parse based on type
        try:
            if sub_type == AppleContinuityType.IBEACON:
                result.ibeacon = AppleContinuityParser._parse_ibeacon(
                    manufacturer_data, sub_type_len
                )

            elif sub_type == AppleContinuityType.NEARBY_INFO:
                result.nearby_info = AppleContinuityParser._parse_nearby_info(
                    manufacturer_data
                )

            elif sub_type == AppleContinuityType.NEARBY_ACTION:
                result.nearby_action = AppleContinuityParser._parse_nearby_action(
                    manufacturer_data
                )

            elif sub_type == AppleContinuityType.FINDMY:
                result.findmy = AppleContinuityParser._parse_findmy(manufacturer_data)

            elif sub_type == AppleContinuityType.AIRPLAY_TARGET:
                result.airplay = AppleContinuityParser._parse_airplay(manufacturer_data)

        except Exception as e:
            result.protocol_error = f"Parse error: {str(e)}"

        return result

    @staticmethod
    def _parse_ibeacon(data: bytes, expected_len: int) -> Optional[IBeaconData]:
        """Parse iBeacon advertisement data.

        iBeacon format (starting at byte 4):
        - Bytes 0-15: Proximity UUID (16 bytes)
        - Bytes 16-17: Major (2 bytes, big-endian)
        - Bytes 18-19: Minor (2 bytes, big-endian)
        - Byte 20: Measured TX Power (1 byte, signed)
        """
        if expected_len != 21:
            return None

        if len(data) < 25:
            return None

        uuid = data[4:20].hex()
        major = int.from_bytes(data[20:22], byteorder="big")
        minor = int.from_bytes(data[22:24], byteorder="big")

        # TX Power is a signed byte
        tx_power = data[24]
        if tx_power > 127:
            tx_power = tx_power - 256

        return IBeaconData(uuid=uuid, major=major, minor=minor, tx_power=tx_power)

    @staticmethod
    def _parse_nearby_info(data: bytes) -> Optional[NearbyInfoData]:
        """Parse NearbyInfo advertisement data.

        NearbyInfo format (starting at byte 4):
        - Byte 0: Combined flags (upper nibble) and action code (lower nibble)
        - Byte 1: Status flags
        """
        if len(data) < 6:
            return None

        combined = data[4]
        flags_nibble = (combined >> 4) & 0x0F
        action_code = combined & 0x0F

        status = data[5]

        action = APPLE_NEARBY_INFO_ACTION_CODES.get(
            action_code, f"unknown(0x{action_code:02x})"
        )

        flags = {
            "primary_device": bool(flags_nibble & 0x01),
            "unknown_flag1": bool(flags_nibble & 0x02),
            "airdrop_rx_enabled": bool(flags_nibble & 0x04),
            "unknown_flag2": bool(flags_nibble & 0x08),
            "airpods_connected_screen_on": bool(status & 0x01),
            "auth_tag_4_bytes": bool(status & 0x02),
            "wifi_on": bool(status & 0x04),
            "has_auth_tag": bool(status & 0x10),
            "watch_locked": bool(status & 0x20),
            "watch_auto_lock": bool(status & 0x40),
            "auto_lock": bool(status & 0x80),
        }

        return NearbyInfoData(action_code=action_code, action=action, flags=flags)

    @staticmethod
    def _parse_nearby_action(data: bytes) -> Optional[NearbyActionData]:
        """Parse NearbyAction advertisement data.

        NearbyAction format (starting at byte 4):
        - Byte 0: Flags
        - Byte 1: Action type
        """
        if len(data) < 6:
            return None

        flags = data[4]
        action_type = data[5]

        action_name = APPLE_NEARBY_ACTION_TYPES.get(
            action_type, f"unknown(0x{action_type:02x})"
        )

        return NearbyActionData(
            action_type=action_type, action_name=action_name, flags=flags
        )

    @staticmethod
    def _parse_findmy(data: bytes) -> Optional[FindMyData]:
        """Parse FindMy advertisement data.

        FindMy format (starting at byte 4):
        - Byte 0: Status byte (bit 2 indicates "maintained" status)
        """
        if len(data) < 5:
            return None

        status = data[4]
        maintained = bool((status >> 2) & 0x01)

        return FindMyData(maintained=maintained)

    @staticmethod
    def _parse_airplay(data: bytes) -> Optional[AirPlayData]:
        """Parse AirPlay Target advertisement data.

        The last 4 bytes typically contain an IP address.
        """
        if len(data) < 8:
            return None

        # IP address is in the last 4 bytes
        ip_bytes = data[-4:]
        ip_address = ".".join(str(b) for b in ip_bytes)

        return AirPlayData(ip_address=ip_address)


def parse_apple_continuity(manufacturer_data: bytes) -> Optional[AppleContinuityResult]:
    """Convenience function to parse Apple Continuity data.

    Args:
        manufacturer_data: Raw manufacturer-specific data bytes

    Returns:
        AppleContinuityResult if the data is from Apple, None otherwise.

    Example:
        >>> data = bytes.fromhex("4c0010050318...")
        >>> result = parse_apple_continuity(data)
        >>> if result and result.nearby_info:
        ...     print(result.nearby_info.action)
    """
    if not AppleContinuityParser.is_apple_manufacturer_data(manufacturer_data):
        return None

    return AppleContinuityParser.parse(manufacturer_data)


def get_apple_device_type_hint(
    continuity_result: AppleContinuityResult,
) -> Optional[str]:
    """Get a hint about the type of Apple device based on continuity data.

    Args:
        continuity_result: Parsed Apple Continuity result

    Returns:
        String describing the likely device type, or None if unknown.
    """
    if continuity_result.ibeacon:
        return "iBeacon"

    if continuity_result.findmy:
        return "AirTag or FindMy-enabled device"

    if continuity_result.nearby_info:
        action = continuity_result.nearby_info.action
        flags = continuity_result.nearby_info.flags

        if "watch" in action.lower() or flags.get("watch_locked"):
            return "Apple Watch"
        if "audio" in action.lower():
            return "AirPods or Beats"
        if flags.get("airpods_connected_screen_on"):
            return "iPhone/iPad with AirPods"

    if continuity_result.type_name == "ProximityPairing":
        return "AirPods, Beats, or Apple Accessory"

    if continuity_result.airplay:
        return "Apple TV or AirPlay-enabled device"

    if continuity_result.type_name == "Handoff":
        return "Mac, iPhone, or iPad"

    return None


# Device model hints from continuity data patterns
APPLE_DEVICE_MODELS: Dict[str, str] = {
    "iphone": "iPhone",
    "ipad": "iPad",
    "macbook": "MacBook",
    "imac": "iMac",
    "watch": "Apple Watch",
    "airpods": "AirPods",
    "airtag": "AirTag",
    "homepod": "HomePod",
    "appletv": "Apple TV",
}
