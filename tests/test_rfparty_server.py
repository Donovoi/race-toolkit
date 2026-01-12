"""Tests for librace/rfparty_server.py - RFParty BLE scanner server."""

import pytest
import time
import json

from librace.rfparty_server import BLEDevice, RFPartyScanner


class TestBLEDevice:
    """Tests for BLEDevice dataclass."""

    def test_device_creation(self):
        """BLEDevice should be created with required fields."""
        device = BLEDevice(address="AA:BB:CC:DD:EE:FF")
        assert device.address == "AA:BB:CC:DD:EE:FF"
        assert device.name is None
        assert device.rssi == -100
        assert device.packet_count == 1

    def test_device_with_all_fields(self):
        """BLEDevice should accept all optional fields."""
        device = BLEDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            rssi=-45,
            address_type="public",
            connectable=True,
            manufacturer_id=0x004C,
            manufacturer_name="Apple",
            services=["0x180F", "0x1800"],
        )
        assert device.name == "Test Device"
        assert device.rssi == -45
        assert device.address_type == "public"
        assert device.connectable is True
        assert device.manufacturer_id == 0x004C
        assert device.manufacturer_name == "Apple"
        assert len(device.services) == 2

    def test_device_to_dict(self):
        """BLEDevice.to_dict() should return JSON-serializable dict."""
        device = BLEDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
        )
        d = device.to_dict()
        assert d["address"] == "AA:BB:CC:DD:EE:FF"
        assert d["name"] == "Test"
        assert d["rssi"] == -50
        assert "durationMs" in d
        # Should be JSON serializable
        json.dumps(d)

    def test_device_raw_advertisement_hex(self):
        """Raw advertisement should be converted to hex in to_dict."""
        device = BLEDevice(
            address="AA:BB:CC:DD:EE:FF",
            raw_advertisement=b"\x01\x02\x03\x04",
        )
        d = device.to_dict()
        assert d["rawAdvertisement"] == "01020304"


class TestRFPartyScanner:
    """Tests for RFPartyScanner class."""

    def test_scanner_creation(self):
        """Scanner should be created with empty device list."""
        scanner = RFPartyScanner()
        assert len(scanner.devices) == 0
        assert scanner.packet_count == 0
        assert scanner.running is False

    def test_scanner_on_device_new(self):
        """on_device should add new device to list."""
        scanner = RFPartyScanner()
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        assert len(scanner.devices) == 1
        assert scanner.packet_count == 1
        assert "AA:BB:CC:DD:EE:FF" in scanner.devices

    def test_scanner_on_device_update(self):
        """on_device should update existing device."""
        scanner = RFPartyScanner()
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name=None,
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        # Second call with name should update
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Now Named",
            rssi=-40,
            address_type="public",
            connectable=True,
        )
        assert len(scanner.devices) == 1
        assert scanner.packet_count == 2
        device = scanner.devices["AA:BB:CC:DD:EE:FF"]
        assert device.name == "Now Named"
        assert device.rssi == -40
        assert device.packet_count == 2

    def test_scanner_set_location(self):
        """set_location should update scanner location."""
        scanner = RFPartyScanner()
        scanner.set_location(40.7128, -74.0060, 10.0)
        assert scanner.location == (40.7128, -74.0060, 10.0)

    def test_scanner_location_applied_to_device(self):
        """Location should be applied to newly discovered devices."""
        scanner = RFPartyScanner()
        scanner.set_location(40.7128, -74.0060, 10.0)
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        device = scanner.devices["AA:BB:CC:DD:EE:FF"]
        assert device.latitude == 40.7128
        assert device.longitude == -74.0060
        assert device.accuracy == 10.0

    def test_scanner_get_all_devices(self):
        """get_all_devices should return list of dicts."""
        scanner = RFPartyScanner()
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Device 1",
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        scanner.on_device(
            address="11:22:33:44:55:66",
            name="Device 2",
            rssi=-60,
            address_type="random",
            connectable=False,
        )
        devices = scanner.get_all_devices()
        assert len(devices) == 2
        assert all(isinstance(d, dict) for d in devices)

    def test_scanner_get_stats(self):
        """get_stats should return scanner statistics."""
        scanner = RFPartyScanner()
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        stats = scanner.get_stats()
        assert stats["deviceCount"] == 1
        assert stats["packetCount"] == 1
        assert stats["running"] is False

    def test_scanner_clear(self):
        """clear should remove all devices."""
        scanner = RFPartyScanner()
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        assert len(scanner.devices) == 1
        scanner.clear()
        assert len(scanner.devices) == 0
        assert scanner.packet_count == 0

    def test_scanner_subscribe_notify(self):
        """Subscribers should receive device notifications."""
        scanner = RFPartyScanner()
        events = []

        def callback(event_type, data):
            events.append((event_type, data))

        scanner.subscribe(callback)
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        assert len(events) == 1
        assert events[0][0] == "device"
        assert events[0][1]["address"] == "AA:BB:CC:DD:EE:FF"

    def test_scanner_unsubscribe(self):
        """Unsubscribed callbacks should not receive events."""
        scanner = RFPartyScanner()
        events = []

        def callback(event_type, data):
            events.append((event_type, data))

        scanner.subscribe(callback)
        scanner.unsubscribe(callback)
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
            address_type="public",
            connectable=True,
        )
        assert len(events) == 0

    def test_scanner_services_merge(self):
        """Services should be merged on device update."""
        scanner = RFPartyScanner()
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
            address_type="public",
            connectable=True,
            services=["0x180F"],
        )
        scanner.on_device(
            address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-50,
            address_type="public",
            connectable=True,
            services=["0x1800"],
        )
        device = scanner.devices["AA:BB:CC:DD:EE:FF"]
        assert "0x180F" in device.services
        assert "0x1800" in device.services
