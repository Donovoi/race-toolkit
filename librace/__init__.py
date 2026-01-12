"""RACE Toolkit Library - BLE/Bluetooth Security Research Tools.

This library provides utilities for:
- RACE protocol communication and exploitation
- BLE advertisement parsing and analysis
- Bluetooth device identification
- Firmware dumping and analysis

Modules:
    ble_tables: Comprehensive BLE UUID lookup tables (GATT services, characteristics, etc.)
    manufacturer_ids: Bluetooth SIG manufacturer company ID database (2840+ entries)
    gap_parser: Generic Access Profile (GAP) advertisement data parser
    apple_continuity: Apple Continuity protocol parser (iBeacon, AirDrop, FindMy, etc.)
    constants: RACE protocol constants and BLE lookup re-exports
    packets: RACE protocol packet definitions
    transport: BLE/RFCOMM/USB transport implementations
    race: RACE protocol handler
    dumper: Memory and flash dumping utilities
    fota: Firmware Over-The-Air update utilities
    parttable: Partition table parsing
    util: General utilities
"""

# Version
__version__ = "1.0.0"

# Core RACE protocol
from librace.race import RACE
from librace.packets import RacePacket, RaceHeader
from librace.dumper import RACEDumper, RACEFlashDumper, RACERAMDumper

# BLE analysis tools
from librace.gap_parser import (
    GapParser,
    ParsedAdvertisement,
    parse_advertisement,
    decode_flags,
)
from librace.apple_continuity import (
    AppleContinuityParser,
    parse_apple_continuity,
    AppleContinuityResult,
)

# Lookup tables
from librace.ble_tables import (
    lookup_uuid16,
    lookup_uuid128,
    lookup_apple_continuity_type,
    GATT_SERVICES,
    GATT_CHARACTERISTICS,
    GATT_DESCRIPTORS,
)
from librace.manufacturer_ids import (
    lookup_manufacturer,
    lookup_manufacturer_by_int,
    parse_manufacturer_data,
    MANUFACTURER_COMPANY_IDS,
)

__all__ = [
    # Version
    "__version__",
    # RACE protocol
    "RACE",
    "RacePacket",
    "RaceHeader",
    "RACEDumper",
    "RACEFlashDumper",
    "RACERAMDumper",
    # GAP parsing
    "GapParser",
    "ParsedAdvertisement",
    "parse_advertisement",
    "decode_flags",
    # Apple Continuity
    "AppleContinuityParser",
    "parse_apple_continuity",
    "AppleContinuityResult",
    # Lookups
    "lookup_uuid16",
    "lookup_uuid128",
    "lookup_apple_continuity_type",
    "lookup_manufacturer",
    "lookup_manufacturer_by_int",
    "parse_manufacturer_data",
    # Data tables
    "GATT_SERVICES",
    "GATT_CHARACTERISTICS",
    "GATT_DESCRIPTORS",
    "MANUFACTURER_COMPANY_IDS",
]
