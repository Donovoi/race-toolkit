"""Tests for race_toolkit.py CLI argument parsing."""

import pytest
import sys


# We need to import parse_args from the main module
# Use importlib to handle the module name with underscores
def get_parse_args():
    """Import parse_args from race_toolkit.py."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("race_toolkit", "race_toolkit.py")
    module = importlib.util.module_from_spec(spec)
    # Don't execute the module (would run main), just load parse_args
    # We need to be careful here - let's mock sys.argv first
    old_argv = sys.argv
    sys.argv = ["race_toolkit.py", "check"]  # Minimal valid args
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
    return module.parse_args


class TestParseArgsBasic:
    """Tests for basic argument parsing."""

    @pytest.fixture(autouse=True)
    def setup_parse_args(self):
        """Load parse_args once for all tests."""
        self.parse_args = get_parse_args()

    def test_check_command(self):
        """Check command should parse correctly."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "check"]
        try:
            args = self.parse_args()
            assert args.command == "check"
        finally:
            sys.argv = old_argv

    def test_default_transport(self):
        """Default transport should be gatt."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "check"]
        try:
            args = self.parse_args()
            assert args.transport == "gatt"
        finally:
            sys.argv = old_argv

    def test_transport_rfcomm(self):
        """RFCOMM transport should be selectable."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "-t", "rfcomm", "check"]
        try:
            args = self.parse_args()
            assert args.transport == "rfcomm"
        finally:
            sys.argv = old_argv

    def test_transport_usb(self):
        """USB transport should be selectable."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "-t", "usb", "check"]
        try:
            args = self.parse_args()
            assert args.transport == "usb"
        finally:
            sys.argv = old_argv

    def test_default_controller(self):
        """Default controller should be usb:0."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "check"]
        try:
            args = self.parse_args()
            assert args.controller == "usb:0"
        finally:
            sys.argv = old_argv

    def test_custom_controller(self):
        """Custom controller should be parsed."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "-c", "usb:0BDA:8771", "check"]
        try:
            args = self.parse_args()
            assert args.controller == "usb:0BDA:8771"
        finally:
            sys.argv = old_argv

    def test_target_address(self):
        """Target address should be parsed."""
        old_argv = sys.argv
        sys.argv = [
            "race_toolkit.py",
            "--target-address",
            "AA:BB:CC:DD:EE:FF",
            "check",
        ]
        try:
            args = self.parse_args()
            assert args.target_address == "AA:BB:CC:DD:EE:FF"
        finally:
            sys.argv = old_argv


class TestParseArgsCommands:
    """Tests for specific command parsing."""

    @pytest.fixture(autouse=True)
    def setup_parse_args(self):
        """Load parse_args once for all tests."""
        self.parse_args = get_parse_args()

    def test_ram_command_with_args(self):
        """RAM command should require address and size."""
        old_argv = sys.argv
        sys.argv = [
            "race_toolkit.py",
            "ram",
            "--address",
            "0x10000000",
            "--size",
            "0x100",
        ]
        try:
            args = self.parse_args()
            assert args.command == "ram"
            assert args.address == 0x10000000
            assert args.size == 0x100
        finally:
            sys.argv = old_argv

    def test_flash_command_with_args(self):
        """Flash command should require address and size."""
        old_argv = sys.argv
        sys.argv = [
            "race_toolkit.py",
            "flash",
            "--address",
            "0x08000000",
            "--size",
            "0x1000",
        ]
        try:
            args = self.parse_args()
            assert args.command == "flash"
            assert args.address == 0x08000000
            assert args.size == 0x1000
        finally:
            sys.argv = old_argv

    def test_bdaddr_command(self):
        """bdaddr command should parse."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "bdaddr"]
        try:
            args = self.parse_args()
            assert args.command == "bdaddr"
        finally:
            sys.argv = old_argv

    def test_sdkinfo_command(self):
        """sdkinfo command should parse."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "sdkinfo"]
        try:
            args = self.parse_args()
            assert args.command == "sdkinfo"
        finally:
            sys.argv = old_argv

    def test_scan_command_default_mode(self):
        """scan command should default to classic mode."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "scan"]
        try:
            args = self.parse_args()
            assert args.command == "scan"
            assert args.mode == "classic"
        finally:
            sys.argv = old_argv

    def test_scan_command_ble_mode(self):
        """scan command should accept ble mode."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "scan", "--mode", "ble"]
        try:
            args = self.parse_args()
            assert args.command == "scan"
            assert args.mode == "ble"
        finally:
            sys.argv = old_argv

    def test_hfp_demo_command(self):
        """hfp-demo command should parse with action."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "hfp-demo", "--action", "answer"]
        try:
            args = self.parse_args()
            assert args.command == "hfp-demo"
            assert args.action == "answer"
        finally:
            sys.argv = old_argv

    def test_raw_command(self):
        """raw command should parse hex ID."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "raw", "--id", "0x5A10"]
        try:
            args = self.parse_args()
            assert args.command == "raw"
            assert args.id == 0x5A10
        finally:
            sys.argv = old_argv

    def test_rfparty_command(self):
        """rfparty command should parse with options."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "rfparty"]
        try:
            args = self.parse_args()
            assert args.command == "rfparty"
            assert args.port == 8888
            assert args.no_browser is False
        finally:
            sys.argv = old_argv

    def test_rfparty_command_with_options(self):
        """rfparty command should accept custom options."""
        old_argv = sys.argv
        sys.argv = [
            "race_toolkit.py",
            "rfparty",
            "--port",
            "9000",
            "--no-browser",
            "--filter",
            "AirPods",
        ]
        try:
            args = self.parse_args()
            assert args.command == "rfparty"
            assert args.port == 9000
            assert args.no_browser is True
            assert args.filter == "AirPods"
        finally:
            sys.argv = old_argv


class TestParseArgsFlags:
    """Tests for global flag parsing."""

    @pytest.fixture(autouse=True)
    def setup_parse_args(self):
        """Load parse_args once for all tests."""
        self.parse_args = get_parse_args()

    def test_debug_flag(self):
        """Debug flag should be parsed."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "--debug", "check"]
        try:
            args = self.parse_args()
            assert args.debug is True
        finally:
            sys.argv = old_argv

    def test_authenticate_flag(self):
        """Authenticate flag should be parsed."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "--authenticate", "check"]
        try:
            args = self.parse_args()
            assert args.authenticate is True
        finally:
            sys.argv = old_argv

    def test_send_delay(self):
        """Send delay should be parsed as float."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "--send-delay", "0.5", "check"]
        try:
            args = self.parse_args()
            assert args.send_delay == 0.5
        finally:
            sys.argv = old_argv

    def test_outfile(self):
        """Outfile should be parsed."""
        old_argv = sys.argv
        sys.argv = ["race_toolkit.py", "--outfile", "output.bin", "check"]
        try:
            args = self.parse_args()
            assert args.outfile == "output.bin"
        finally:
            sys.argv = old_argv
