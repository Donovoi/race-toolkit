"""Tests for librace/manufacturer_ids.py - Bluetooth manufacturer ID database."""

import pytest

from librace.manufacturer_ids import (
    MANUFACTURER_COMPANY_IDS,
    lookup_manufacturer,
    lookup_manufacturer_by_int,
    parse_manufacturer_data,
    APPLE_COMPANY_ID,
    MICROSOFT_COMPANY_ID,
    GOOGLE_COMPANY_ID,
    SAMSUNG_COMPANY_ID,
    SONY_COMPANY_ID,
    BOSE_COMPANY_ID,
)


class TestManufacturerTable:
    """Tests for manufacturer ID table."""

    def test_table_has_apple(self):
        """Apple (0x004C) should be in table."""
        assert "004c" in MANUFACTURER_COMPANY_IDS
        assert "Apple" in MANUFACTURER_COMPANY_IDS["004c"]

    def test_table_has_microsoft(self):
        """Microsoft (0x0006) should be in table."""
        assert "0006" in MANUFACTURER_COMPANY_IDS
        assert "Microsoft" in MANUFACTURER_COMPANY_IDS["0006"]

    def test_table_has_google(self):
        """Google (0x00E0) should be in table."""
        assert "00e0" in MANUFACTURER_COMPANY_IDS

    def test_table_has_sony(self):
        """Sony (0x012D) should be in table."""
        assert "012d" in MANUFACTURER_COMPANY_IDS

    def test_well_known_constants(self):
        """Well-known company ID constants should match table."""
        assert APPLE_COMPANY_ID == "004c"
        assert MICROSOFT_COMPANY_ID == "0006"
        assert GOOGLE_COMPANY_ID == "00e0"
        assert SAMSUNG_COMPANY_ID == "0075"
        assert SONY_COMPANY_ID == "012d"
        assert BOSE_COMPANY_ID == "009e"


class TestLookupManufacturer:
    """Tests for manufacturer lookup by hex string."""

    def test_lookup_apple(self):
        """Looking up Apple company ID should return Apple name."""
        result = lookup_manufacturer("004c")
        assert result is not None
        assert "Apple" in result

    def test_lookup_uppercase(self):
        """Lookup should be case-insensitive."""
        result = lookup_manufacturer("004C")
        assert result is not None
        assert "Apple" in result

    def test_lookup_microsoft(self):
        """Looking up Microsoft should work."""
        result = lookup_manufacturer("0006")
        assert result is not None
        assert "Microsoft" in result

    def test_lookup_unknown(self):
        """Unknown company ID should return None."""
        result = lookup_manufacturer("FFFF")
        assert result is None

    def test_lookup_with_int_param(self):
        """Lookup should handle integer input."""
        # Apple is 0x004C = 76 decimal
        result = lookup_manufacturer(0x004C)
        assert result is not None
        assert "Apple" in result


class TestLookupManufacturerByInt:
    """Tests for manufacturer lookup by integer."""

    def test_lookup_apple_by_int(self):
        """Looking up Apple by integer (76) should work."""
        result = lookup_manufacturer_by_int(76)
        assert result is not None
        assert "Apple" in result

    def test_lookup_microsoft_by_int(self):
        """Looking up Microsoft by integer (6) should work."""
        result = lookup_manufacturer_by_int(6)
        assert result is not None
        assert "Microsoft" in result

    def test_lookup_unknown_by_int(self):
        """Unknown integer ID should return None."""
        result = lookup_manufacturer_by_int(0xFFFF)
        assert result is None


class TestParseManufacturerData:
    """Tests for manufacturer data parsing."""

    def test_parse_apple_data(self):
        """Apple manufacturer data should be correctly parsed."""
        # Apple company ID (0x004C) in little-endian + payload
        data = bytes([0x4C, 0x00, 0x02, 0x15, 0xAA, 0xBB])
        company_name, payload = parse_manufacturer_data(data)

        assert company_name is not None
        assert "Apple" in company_name
        assert payload == bytes([0x02, 0x15, 0xAA, 0xBB])

    def test_parse_microsoft_data(self):
        """Microsoft manufacturer data should be correctly parsed."""
        # Microsoft company ID (0x0006) in little-endian + payload
        data = bytes([0x06, 0x00, 0x01, 0x02, 0x03])
        company_name, payload = parse_manufacturer_data(data)

        assert company_name is not None
        assert "Microsoft" in company_name
        assert payload == bytes([0x01, 0x02, 0x03])

    def test_parse_unknown_manufacturer(self):
        """Unknown manufacturer should return None for name."""
        # Unknown company ID (0xFFFF) in little-endian
        data = bytes([0xFF, 0xFF, 0xAA, 0xBB])
        company_name, payload = parse_manufacturer_data(data)

        assert company_name is None
        assert payload == bytes([0xAA, 0xBB])

    def test_parse_short_data(self):
        """Data shorter than 2 bytes should return None and original data."""
        data = bytes([0x4C])  # Only 1 byte
        company_name, payload = parse_manufacturer_data(data)

        assert company_name is None
        assert payload == data

    def test_parse_empty_data(self):
        """Empty data should return None and empty bytes."""
        data = bytes()
        company_name, payload = parse_manufacturer_data(data)

        assert company_name is None
        assert payload == data

    def test_parse_only_company_id(self):
        """Data with only company ID (no payload) should work."""
        data = bytes([0x4C, 0x00])  # Just Apple company ID
        company_name, payload = parse_manufacturer_data(data)

        assert company_name is not None
        assert "Apple" in company_name
        assert payload == bytes()
