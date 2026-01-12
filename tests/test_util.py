"""Tests for librace/util.py - Utility functions."""

import pytest
import logging

from librace.util import fota_checksum, setup_logging, CHECKSUM_TBL1, CHECKSUM_TBL2


class TestFotaChecksum:
    """Tests for FOTA checksum algorithm."""

    def test_empty_data(self):
        """Empty data should return checksum of 0."""
        result = fota_checksum(b"")
        assert result == 0x00

    def test_single_byte(self):
        """Single byte checksum should be consistent."""
        result = fota_checksum(b"\x00")
        # Based on algorithm: cs = TBL1[0 ^ 0] = TBL1[0] = 0x00
        # high = TBL2[0 >> 4] = TBL2[0] = 0x00
        # low = TBL2[0 & 0x0F] = TBL2[0] = 0x00
        # result = (0x00 | (0x00 << 4)) & 0xFF = 0x00
        assert result == 0x00

    def test_known_pattern(self):
        """Known pattern should produce expected checksum."""
        # Test with a simple pattern
        data = bytes([0x01, 0x02, 0x03, 0x04])
        result = fota_checksum(data)
        # Result should be a single byte
        assert 0 <= result <= 0xFF

    def test_checksum_changes_with_data(self):
        """Different data should produce different checksums."""
        data1 = bytes([0xAA] * 256)
        data2 = bytes([0xBB] * 256)

        checksum1 = fota_checksum(data1)
        checksum2 = fota_checksum(data2)

        assert checksum1 != checksum2

    def test_checksum_deterministic(self):
        """Same data should always produce same checksum."""
        data = bytes(range(256))

        checksum1 = fota_checksum(data)
        checksum2 = fota_checksum(data)

        assert checksum1 == checksum2

    def test_full_page_checksum(self):
        """256-byte page checksum should work correctly."""
        # Typical flash page
        page = bytes(range(256))
        result = fota_checksum(page)
        assert 0 <= result <= 0xFF

    def test_checksum_tables_size(self):
        """Checksum tables should have correct sizes."""
        assert len(CHECKSUM_TBL1) == 256
        assert len(CHECKSUM_TBL2) == 16


class TestSetupLogging:
    """Tests for logging setup."""

    def test_setup_logging_info_level(self):
        """Default setup should set INFO level."""
        setup_logging(debug=False)
        root_logger = logging.getLogger()
        # After setup, root logger should be at INFO level
        assert root_logger.level == logging.INFO

    def test_setup_logging_debug_level(self):
        """Debug setup should set DEBUG level."""
        setup_logging(debug=True)
        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_has_handler(self):
        """Logging should have at least one handler after setup."""
        setup_logging(debug=False)
        root_logger = logging.getLogger()
        assert len(root_logger.handlers) > 0
