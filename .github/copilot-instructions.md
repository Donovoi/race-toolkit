# RACE Toolkit - AI Agent Instructions

## Project Overview

This is a Python-based security research toolkit for Airoha Bluetooth chipsets, focusing on the proprietary **RACE protocol**. It discovers and demonstrates vulnerabilities (CVE-2025-20700/701/702) in Bluetooth devices.

## Architecture

```
race_toolkit.py          # Main CLI (~10K lines) - all commands defined here
librace/
├── race.py              # RACE protocol handler - packet send/recv, fragmentation
├── transport.py         # BLE/Classic/USB transport implementations (Bumble & Bleak)
├── packets.py           # RACE packet definitions (RaceHeader, RacePacket subclasses)
├── dumper.py            # Memory/Flash dump classes with progress bars
├── fota.py              # Firmware update implementation
├── constants.py         # RaceId/RaceType enums, UUIDs (re-exports from other modules)
├── ble_tables.py        # BLE UUID lookup tables (GATT services, characteristics)
├── manufacturer_ids.py  # Bluetooth company ID database
├── parttable.py         # Flash partition table parser
└── rfparty_server.py    # RFParty-style BLE scanner with web UI
```

### RFParty Integration

The `rfparty` command provides a web-based BLE scanner UI inspired by the [rfparty mobile app](https://github.com/datapartyjs/rfparty-mobile).

**Current implementation** (Python backend):

- **Python BLE scanning** via Bumble (requires USB dongle)
- **Leaflet maps** for device visualization
- **Server-Sent Events** for real-time updates to browser
- **Embedded HTML/CSS/JS** in `rfparty_server.py` (no external dependencies)

**Future: WebAssembly Build** (planned for `~/rfparty-mobile-fork`):
The goal is to compile rfparty to WASM so it runs entirely in the browser on any device using Web Bluetooth API. This eliminates the need for a Python backend or USB dongle.

**Related external repo**: `~/rfparty-mobile-fork` contains the rfparty fork being developed for WASM compilation. This is kept separate since it's a JavaScript/TypeScript project with different tooling. The two approaches:

| Feature      | Python (`rfparty` cmd)  | WASM (rfparty-mobile-fork) |
| ------------ | ----------------------- | -------------------------- |
| BLE Access   | Bumble via USB dongle   | Web Bluetooth API          |
| Runs on      | Linux/macOS with dongle | Any device with browser    |
| Dependencies | Python, bumble          | None (static WASM)         |
| Deployment   | Local CLI               | Static hosting anywhere    |

**Running RFParty scanner** (current Python version):

```bash
uv run python race_toolkit.py -c usb:0 rfparty
uv run python race_toolkit.py -c usb:0 rfparty --port 9000 --no-browser
uv run python race_toolkit.py -c usb:0 rfparty --filter "AirPods" --timeout 60
```

**Building rfparty-mobile-fork for WASM** (work in progress):

```bash
cd ~/rfparty-mobile-fork
npm install
npm run build:wasm    # Compiles to WebAssembly
npm run serve         # Serves static WASM build locally
```

**WASM architecture notes**:

- Uses [Emscripten](https://emscripten.org/) or [wasm-pack](https://rustwasm.github.io/wasm-pack/) for compilation
- Web Bluetooth API provides BLE access (Chrome, Edge, Opera - not Firefox/Safari)
- Geolocation via browser's `navigator.geolocation`
- IndexedDB for local data persistence
- Can be hosted as static files on GitHub Pages, Netlify, etc.

### Key Patterns

**Transport Abstraction**: All Bluetooth/USB communication uses `Transport` base class:

- `GATTBumbleTransport` / `GATTBleakTransport` - BLE GATT via Bumble or Bleak
- `RFCOMMTransport` - Bluetooth Classic via Bumble
- `USBHIDTransport` - USB HID direct communication

**RACE Protocol Flow**:

1. Initialize transport → `transport.setup(recv_callback)`
2. Create `RACE(transport, send_delay)` instance
3. Send packets via `race.send_sync(packet)` (blocking) or `race.send(packet)`
4. Packets are `RacePacket` subclasses in [packets.py](librace/packets.py)

**Packet Structure** (all use `struct.pack`/`unpack` with little-endian `<`):

```python
class RaceHeader:  # 6 bytes: head(1) + type(1) + length(2) + id(2)
class RacePacket:  # header + payload, auto-sets length
```

## Code Conventions

**Adding a new CLI command**:

1. Add subparser in `parse_args()` (~line 820 in race_toolkit.py)
2. Add `async def command_<name>(args)` function
3. Wire it in the main dispatch (~line 9800): `elif args.command == "name":`

**Adding a new RACE packet**:

1. Define in [packets.py](librace/packets.py) extending `RacePacket`
2. Add command ID to `RaceId` enum in [constants.py](librace/constants.py)
3. Use `struct.pack/unpack` with `PREAMBLE_FORMAT` pattern

**Transport setup pattern**:

```python
transport = init_transport(args)  # Creates appropriate transport
r = RACE(transport, args.send_delay)
await r.setup()
response = await r.send_sync(SomePacket())  # Returns bytes
await transport.close()
```

**Error handling**: Use logging module, not print. Errors should `sys.exit(1)`.

**Linting**: Run `ruff check .` and `ruff format .` before committing.

## Test-Driven Development

**All new code must have tests.** Follow TDD: write tests first, then implement code to pass them.

**Test location**: Place tests in `tests/` mirroring the source structure:

```
tests/
├── test_packets.py      # Tests for librace/packets.py
├── test_race.py         # Tests for librace/race.py
├── test_transport.py    # Tests for librace/transport.py (mock hardware)
├── test_dumper.py       # Tests for librace/dumper.py
├── test_parttable.py    # Tests for librace/parttable.py
└── test_cli.py          # Tests for race_toolkit.py CLI parsing
```

**Running tests**:

```bash
uv run pytest tests/ -v
uv run pytest tests/ --cov=librace --cov-report=term-missing  # With coverage
```

**Testing patterns for this codebase**:

1. **Packet serialization** - Test `pack()` and `unpack()` round-trips:

```python
def test_race_header_roundtrip():
    header = RaceHeader(head=0x05, type_=0x5A, id_=0x1234, length=10)
    packed = header.pack()
    unpacked = RaceHeader.unpack(packed)
    assert unpacked.head == 0x05
    assert unpacked.id == 0x1234
```

2. **Transport mocking** - Mock Bluetooth hardware for unit tests:

```python
class MockTransport(Transport):
    def __init__(self):
        self.sent_data = []
        self.responses = []
    async def setup(self, recv_fn): self.recv_fn = recv_fn
    async def send(self, data): self.sent_data.append(data)
    async def close(self): pass
```

3. **RACE protocol** - Test fragmentation, response handling:

```python
async def test_race_send_sync():
    transport = MockTransport()
    race = RACE(transport, send_delay=0)
    # Simulate response callback
    asyncio.get_event_loop().call_soon(
        lambda: race._recv(expected_response_bytes)
    )
    result = await race.send_sync(SomePacket())
    assert result == expected_response_bytes
```

4. **CLI argument parsing** - Test `parse_args()` without running commands:

```python
def test_parse_check_command():
    args = parse_args(['check'])
    assert args.command == 'check'
```

**Coverage goal**: 100% of `librace/` modules. CLI commands may have lower coverage due to hardware dependencies.

## Critical Dependencies

- **bumble** (0.0.208): Bluetooth stack for BLE/Classic. Requires USB Bluetooth dongle.
- **bleak**: Alternative BLE stack using OS Bluetooth (limited features)
- **rich**: Terminal UI (tables, progress bars)
- **tqdm**: Progress bars for dumps
- **hid**: USB HID access (optional, for `--transport usb`)

## Running Commands

```bash
# With uv (preferred)
uv run python race_toolkit.py -c usb:0 check

# With venv
source .venv/bin/activate
python race_toolkit.py -c usb:0 --target-address AA:BB:CC:DD:EE:FF ble-info
```

**Controller flag**: `-c usb:0` or `-c usb:VID:PID` for Bumble transports.

## Common Pitfalls

1. **Bluetooth controller busy**: Tool auto-releases with `release_bluetooth_controller()`. May need `sudo systemctl stop bluetooth`.

2. **Address type for BLE**: Use `/P` (public) or `/R` (random) suffix if auto-detect fails: `AA:BB:CC:DD:EE:FF/P`

3. **Bumble requires Python 3.10+**: Check version if imports fail.

4. **Realtek dongles need firmware**: Set `BUMBLE_RTK_FIRMWARE_DIR` or install `linux-firmware`.

5. **Large CLI file**: Search for command names like `"check"` or function names like `command_check` to navigate.

## Vendor UUID Patterns

Known RACE service UUIDs in [constants.py](librace/constants.py):

- Airoha GATT: `5052494D-2DAB-0341-6972-6F6861424C45`
- Sony GATT: `dc405470-a351-4a59-97d8-2e2e3b207fbb`
- Airoha SPP: `00000000-0000-0000-0099-AABBCCDDEEFF`
- Sony SPP: `8901DFA8-5C7E-4D8F-9F0C-C2B70683F5F0`

## Output Formatting

Use `rich` library helpers in race_toolkit.py:

```python
table = create_table([{"name": "Col", "justify": "right"}], title="Title")
table.add_row("value")
print_table(table)
```

## Adding BLE Lookup Data

Extend [ble_tables.py](librace/ble_tables.py) or [manufacturer_ids.py](librace/manufacturer_ids.py) for new UUIDs/company IDs. Both export lookup functions used throughout.
