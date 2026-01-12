"""Tests for librace/parttable.py - Flash partition table parser."""

import pytest
import struct

from librace.parttable import parse_partition_table


class TestParsePartitionTable:
    """Tests for partition table parsing."""

    def test_empty_partition_table(self):
        """Empty table with terminator should return empty list."""
        # Create minimal data with 0x0C header + terminator entry
        header = bytes([0] * 0x0C)
        # Terminator: address=0xFFFFFFFF, length=0xFFFFFFFF, type=0xFF
        terminator = struct.pack("<I", 0xFFFFFFFF)  # address
        terminator += bytes([0] * 4)  # padding
        terminator += struct.pack("<I", 0xFFFFFFFF)  # length
        terminator += bytes([0] * 24)  # padding to offset 36
        terminator += bytes([0xFF])  # ptype
        terminator += bytes([0] * 11)  # remaining padding to 48 bytes

        data = header + terminator

        result = parse_partition_table(data)
        assert result == []

    def test_single_partition(self):
        """Single partition should be parsed correctly."""
        header = bytes([0] * 0x0C)

        # First partition entry
        entry1 = struct.pack("<I", 0x08000000)  # address
        entry1 += bytes([0] * 4)  # padding
        entry1 += struct.pack("<I", 0x00100000)  # length (1MB)
        entry1 += bytes([0] * 24)  # padding to offset 36
        entry1 += bytes([0x01])  # ptype = 1
        entry1 += bytes([0] * 11)  # remaining padding

        # Terminator entry
        terminator = struct.pack("<I", 0xFFFFFFFF)
        terminator += bytes([0] * 4)
        terminator += struct.pack("<I", 0xFFFFFFFF)
        terminator += bytes([0] * 24)
        terminator += bytes([0xFF])
        terminator += bytes([0] * 11)

        data = header + entry1 + terminator

        result = parse_partition_table(data)
        assert len(result) == 1
        assert result[0] == (0x08000000, 0x00100000, 0x01)

    def test_multiple_partitions(self):
        """Multiple partitions should be parsed in order."""
        header = bytes([0] * 0x0C)

        partitions_data = []
        expected = [
            (0x08000000, 0x00010000, 0x00),  # Bootloader
            (0x08010000, 0x00080000, 0x01),  # Firmware
            (0x08090000, 0x00010000, 0x06),  # NVDM
        ]

        for addr, length, ptype in expected:
            entry = struct.pack("<I", addr)
            entry += bytes([0] * 4)
            entry += struct.pack("<I", length)
            entry += bytes([0] * 24)
            entry += bytes([ptype])
            entry += bytes([0] * 11)
            partitions_data.append(entry)

        # Terminator
        terminator = struct.pack("<I", 0xFFFFFFFF)
        terminator += bytes([0] * 4)
        terminator += struct.pack("<I", 0xFFFFFFFF)
        terminator += bytes([0] * 24)
        terminator += bytes([0xFF])
        terminator += bytes([0] * 11)

        data = header + b"".join(partitions_data) + terminator

        result = parse_partition_table(data)
        assert len(result) == 3
        assert result == expected

    def test_partition_type_255_terminates(self):
        """Partition type 255 should terminate parsing after being added."""
        header = bytes([0] * 0x0C)

        # Valid partition
        entry1 = struct.pack("<I", 0x08000000)
        entry1 += bytes([0] * 4)
        entry1 += struct.pack("<I", 0x00100000)
        entry1 += bytes([0] * 24)
        entry1 += bytes([0x01])
        entry1 += bytes([0] * 11)

        # Type 255 entry (added then terminates)
        entry2 = struct.pack("<I", 0x08100000)
        entry2 += bytes([0] * 4)
        entry2 += struct.pack("<I", 0x00100000)
        entry2 += bytes([0] * 24)
        entry2 += bytes([0xFF])  # type 255 terminates
        entry2 += bytes([0] * 11)

        # This should not be parsed
        entry3 = struct.pack("<I", 0x08200000)
        entry3 += bytes([0] * 4)
        entry3 += struct.pack("<I", 0x00100000)
        entry3 += bytes([0] * 24)
        entry3 += bytes([0x02])
        entry3 += bytes([0] * 11)

        data = header + entry1 + entry2 + entry3

        result = parse_partition_table(data)
        # Type 255 entry is added before loop terminates, so we get 2 entries
        assert len(result) == 2
        assert result[0][0] == 0x08000000
        assert result[1][2] == 0xFF  # Type 255 is included

    def test_typical_device_layout(self):
        """Test parsing a typical Airoha device partition layout."""
        header = bytes([0] * 0x0C)

        # Typical layout from real device
        layout = [
            (0x08000000, 0x00003000, 0x00),  # 0: Boot header
            (0x08003000, 0x0000D000, 0x01),  # 1: Bootloader
            (0x08010000, 0x00002000, 0x02),  # 2: Partition table
            (0x08012000, 0x0000E000, 0x03),  # 3: Config
            (0x08020000, 0x00180000, 0x04),  # 4: Firmware
            (0x081A0000, 0x00040000, 0x05),  # 5: FOTA
            (0x081E0000, 0x00020000, 0x06),  # 6: NVDM
        ]

        entries = []
        for addr, length, ptype in layout:
            entry = struct.pack("<I", addr)
            entry += bytes([0] * 4)
            entry += struct.pack("<I", length)
            entry += bytes([0] * 24)
            entry += bytes([ptype])
            entry += bytes([0] * 11)
            entries.append(entry)

        # Terminator
        terminator = struct.pack("<I", 0xFFFFFFFF)
        terminator += bytes([0] * 4)
        terminator += struct.pack("<I", 0xFFFFFFFF)
        terminator += bytes([0] * 24)
        terminator += bytes([0xFF])
        terminator += bytes([0] * 11)

        data = header + b"".join(entries) + terminator

        result = parse_partition_table(data)
        assert len(result) == 7
        assert result == layout
