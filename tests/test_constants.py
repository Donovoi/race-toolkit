"""Tests for librace/constants.py - RACE protocol constants and enums."""

import pytest

from librace.constants import RaceId, RaceType, UuidTable


class TestRaceId:
    """Tests for RACE command ID enum."""

    def test_fota_commands_exist(self):
        """FOTA-related command IDs should be defined."""
        assert RaceId.RACE_FOTA_COMMIT == 0x1C02
        assert RaceId.RACE_FOTA_INTEGRITY_CHECK == 0x1C01
        assert RaceId.RACE_FOTA_PARTITION_INFO_QUERY == 0x1C00
        assert RaceId.RACE_FOTA_START == 0x1C08
        assert RaceId.RACE_FOTA_START_TRANSCATION == 0x1C0A
        assert RaceId.RACE_FOTA_STOP == 0x1C03
        assert RaceId.RACE_FOTA_WRITE_STATE == 0x1C06

    def test_storage_commands_exist(self):
        """Storage-related command IDs should be defined."""
        assert RaceId.RACE_STORAGE_PAGE_PROGRAM == 0x402
        assert RaceId.RACE_STORAGE_PAGE_READ == 0x403
        assert RaceId.RACE_STORAGE_PARTITION_ERASE == 0x404

    def test_info_commands_exist(self):
        """Info retrieval command IDs should be defined."""
        assert RaceId.RACE_GET_LINK_KEY == 0xCC0
        assert RaceId.RACE_GET_BD_ADDRESS == 0xCD5
        assert RaceId.RACE_READ_ADDRESS == 0x1680
        assert RaceId.RACE_READ_SDK_VERSION == 0x0301
        assert RaceId.RACE_GET_BUILD_VERSION == 0x1E08


class TestRaceType:
    """Tests for RACE packet type enum."""

    def test_cmd_expects_response(self):
        """CMD_EXPECTS_RESPONSE should be 0x5A."""
        assert RaceType.CMD_EXPECTS_RESPONSE == 0x5A

    def test_cmd_expects_no_response(self):
        """CMD_EXPECTS_NO_RESPONSE should be 0x5C."""
        assert RaceType.CMD_EXPECTS_NO_RESPONSE == 0x5C

    def test_indication(self):
        """INDICATION should be 0x5D."""
        assert RaceType.INDICATION == 0x5D

    def test_response(self):
        """RESPONSE should be 0x5B."""
        assert RaceType.RESPONSE == 0x5B


class TestUuidTable:
    """Tests for known RACE UUIDs."""

    def test_airoha_spp_uuid(self):
        """Airoha SPP UUID should be defined."""
        assert str(UuidTable.AIROHA_SPP_UUID) == "00000000-0000-0000-0099-AABBCCDDEEFF"

    def test_sony_spp_uuid(self):
        """Sony SPP UUID should be defined."""
        assert str(UuidTable.SONY_SPP_UUID) == "8901DFA8-5C7E-4D8F-9F0C-C2B70683F5F0"

    def test_airoha_gatt_service_uuid(self):
        """Airoha GATT Service UUID should be defined."""
        assert (
            str(UuidTable.AIROHA_GATT_SERVICE_UUID)
            == "5052494D-2DAB-0341-6972-6F6861424C45"
        )

    def test_sony_gatt_service_uuid(self):
        """Sony GATT Service UUID should be defined."""
        assert (
            str(UuidTable.SONY_GATT_SERVICE_UUID)
            == "DC405470-A351-4A59-97D8-2E2E3B207FBB"
        )

    def test_airoha_gatt_tx_rx_uuids(self):
        """Airoha GATT TX/RX UUIDs should be defined."""
        assert UuidTable.AIROHA_GATT_TX_UUID is not None
        assert UuidTable.AIROHA_GATT_RX_UUID is not None

    def test_common_spp_uuid(self):
        """Common SPP UUID should be standard Serial Port Profile UUID."""
        assert str(UuidTable.COMMON_SPP_UUID) == "00001101-0000-1000-8000-00805F9B34FB"
