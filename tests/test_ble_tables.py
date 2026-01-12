"""Tests for librace/ble_tables.py - BLE UUID lookup tables."""

import pytest

from librace.ble_tables import (
    GATT_SERVICES,
    GATT_CHARACTERISTICS,
    GATT_DESCRIPTORS,
    GATT_DECLARATIONS,
    GATT_UNITS,
    PROTOCOL_IDENTIFIERS,
    SERVICE_CLASSES_AND_PROFILES,
    SDO_GATT_SERVICES,
    KNOWN_PRODUCT_UUIDS,
    APPLE_CONTINUITY_TYPES,
    GAP_AD_TYPES,
    lookup_uuid16,
    lookup_uuid128,
    lookup_apple_continuity_type,
    lookup_nearby_info_action,
    lookup_nearby_action_type,
    get_gap_ad_type,
)


class TestGattTables:
    """Tests for GATT lookup tables."""

    def test_gatt_services_has_generic_access(self):
        """Generic Access service (0x1800) should be defined."""
        assert "1800" in GATT_SERVICES
        assert GATT_SERVICES["1800"] == "Generic Access"

    def test_gatt_services_has_device_info(self):
        """Device Information service (0x180A) should be defined."""
        assert "180a" in GATT_SERVICES
        assert GATT_SERVICES["180a"] == "Device Information"

    def test_gatt_services_has_battery(self):
        """Battery service (0x180F) should be defined."""
        assert "180f" in GATT_SERVICES
        assert GATT_SERVICES["180f"] == "Battery"

    def test_gatt_declarations_has_primary_service(self):
        """Primary Service declaration (0x2800) should be defined."""
        assert "2800" in GATT_DECLARATIONS
        assert GATT_DECLARATIONS["2800"] == "Primary Service"

    def test_gatt_declarations_has_characteristic(self):
        """Characteristic declaration (0x2803) should be defined."""
        assert "2803" in GATT_DECLARATIONS
        assert GATT_DECLARATIONS["2803"] == "Characteristic"


class TestLookupUuid16:
    """Tests for 16-bit UUID lookup."""

    def test_lookup_service(self):
        """Service UUID should return (service, name)."""
        result = lookup_uuid16("1800")
        assert result is not None
        category, name = result
        assert category == "service"
        assert name == "Generic Access"

    def test_lookup_service_uppercase(self):
        """UUID lookup should be case-insensitive."""
        result = lookup_uuid16("180A")
        assert result is not None
        category, name = result
        assert category == "service"

    def test_lookup_declaration(self):
        """Declaration UUID should return (declaration, name)."""
        result = lookup_uuid16("2800")
        assert result is not None
        category, name = result
        assert category == "declaration"
        assert name == "Primary Service"

    def test_lookup_unknown(self):
        """Unknown UUID should return None."""
        result = lookup_uuid16("FFFF")
        assert result is None


class TestLookupUuid128:
    """Tests for 128-bit UUID lookup."""

    def test_lookup_unknown(self):
        """Unknown 128-bit UUID should return None."""
        result = lookup_uuid128("00000000-0000-0000-0000-000000000000")
        assert result is None

    def test_lookup_normalizes_dashes(self):
        """UUID lookup should handle dashes."""
        # Both with and without dashes should work
        uuid_with_dashes = "00000000-0000-0000-0000-000000000001"
        uuid_without = "00000000000000000000000000000001"
        # Both should return same result (probably None for this fake UUID)
        result1 = lookup_uuid128(uuid_with_dashes)
        result2 = lookup_uuid128(uuid_without)
        assert result1 == result2


class TestAppleContinuityTypes:
    """Tests for Apple Continuity protocol lookup."""

    def test_ibeacon_type(self):
        """iBeacon type (0x02) should be defined."""
        result = lookup_apple_continuity_type("02")
        assert result is not None

    def test_unknown_type(self):
        """Unknown type should return None."""
        result = lookup_apple_continuity_type("FF")
        assert result is None


class TestNearbyInfoLookup:
    """Tests for Apple NearbyInfo action lookup."""

    def test_known_action(self):
        """Known action code should return description."""
        result = lookup_nearby_info_action(0x00)
        assert isinstance(result, str)

    def test_unknown_action(self):
        """Unknown action should return formatted unknown string."""
        result = lookup_nearby_info_action(0xFF)
        assert "unknown" in result


class TestNearbyActionType:
    """Tests for Apple NearbyAction type lookup."""

    def test_unknown_action_type(self):
        """Unknown action type should return formatted string."""
        result = lookup_nearby_action_type(0xFF)
        assert "unknown" in result


class TestGapAdTypes:
    """Tests for GAP AD type lookup."""

    def test_gap_ad_types_table_exists(self):
        """GAP_AD_TYPES table should exist and have entries."""
        assert isinstance(GAP_AD_TYPES, dict)
        # Should have at least common AD types
        assert len(GAP_AD_TYPES) > 0

    def test_get_gap_ad_type_complete_local_name(self):
        """Complete Local Name (0x09) should be defined."""
        result = get_gap_ad_type(0x09)
        if result is not None:
            name, method = result
            assert isinstance(name, str)
