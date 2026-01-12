"""RFParty-style BLE scanner with web UI.

This module provides a local web server that displays BLE scan results
on an interactive map, similar to the rfparty mobile app. It uses
race-toolkit's existing BLE scanning infrastructure and serves a
web interface for viewing and interacting with discovered devices.

The server communicates with the frontend via Server-Sent Events (SSE)
for real-time device updates.
"""

import asyncio
import json
import logging
import os
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Path to rfparty-mobile-fork repository (configurable)
RFPARTY_REPO_PATH = os.environ.get(
    "RFPARTY_REPO_PATH", os.path.expanduser("~/rfparty-mobile-fork")
)


@dataclass
class BLEDevice:
    """Represents a discovered BLE device."""

    address: str
    name: str | None = None
    rssi: int = -100
    address_type: str = "unknown"  # public, random
    connectable: bool = False
    manufacturer_id: int | None = None
    manufacturer_name: str | None = None
    services: list[str] = field(default_factory=list)
    raw_advertisement: bytes = b""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 1
    latitude: float | None = None
    longitude: float | None = None
    accuracy: float | None = None

    # Parsed advertisement data
    tx_power: int | None = None
    appearance: int | None = None
    flags: int | None = None
    service_data: dict[str, str] = field(default_factory=dict)

    # Apple-specific
    apple_continuity_type: str | None = None
    apple_device_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "addressType": self.address_type,
            "connectable": self.connectable,
            "manufacturerId": self.manufacturer_id,
            "manufacturerName": self.manufacturer_name,
            "services": self.services,
            "rawAdvertisement": self.raw_advertisement.hex()
            if self.raw_advertisement
            else "",
            "firstSeen": self.first_seen,
            "lastSeen": self.last_seen,
            "packetCount": self.packet_count,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "accuracy": self.accuracy,
            "txPower": self.tx_power,
            "appearance": self.appearance,
            "flags": self.flags,
            "serviceData": self.service_data,
            "appleContinuityType": self.apple_continuity_type,
            "appleDeviceStatus": self.apple_device_status,
            "durationMs": int((self.last_seen - self.first_seen) * 1000),
        }


class RFPartyScanner:
    """BLE scanner that feeds data to the web UI."""

    def __init__(self, controller: str = "usb:0"):
        self.controller = controller
        self.devices: dict[str, BLEDevice] = {}
        self.running = False
        self.packet_count = 0
        self.location: tuple[float, float, float] | None = None  # lat, lon, accuracy
        self._scan_task: asyncio.Task | None = None
        self._subscribers: list[Callable[[str, Any], None]] = []

    def subscribe(self, callback: Callable[[str, Any], None]):
        """Subscribe to device updates. Callback receives (event_type, data)."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[str, Any], None]):
        """Unsubscribe from updates."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _notify(self, event_type: str, data: Any):
        """Notify all subscribers of an event."""
        for callback in self._subscribers:
            try:
                callback(event_type, data)
            except Exception as e:
                logger.error(f"Subscriber callback error: {e}")

    def set_location(self, latitude: float, longitude: float, accuracy: float):
        """Set current GPS location for tagging devices."""
        self.location = (latitude, longitude, accuracy)
        self._notify(
            "location",
            {"latitude": latitude, "longitude": longitude, "accuracy": accuracy},
        )

    def on_device(
        self,
        address: str,
        name: str | None,
        rssi: int,
        address_type: str,
        connectable: bool,
        advertisement_data: bytes | None = None,
        services: list[str] | None = None,
        manufacturer_id: int | None = None,
        manufacturer_name: str | None = None,
        **kwargs,
    ):
        """Called when a BLE device is discovered or updated."""
        self.packet_count += 1

        if address in self.devices:
            device = self.devices[address]
            device.rssi = rssi
            device.last_seen = time.time()
            device.packet_count += 1
            if name and not device.name:
                device.name = name
            if services:
                device.services = list(set(device.services + services))
        else:
            device = BLEDevice(
                address=address,
                name=name,
                rssi=rssi,
                address_type=address_type,
                connectable=connectable,
                manufacturer_id=manufacturer_id,
                manufacturer_name=manufacturer_name,
                services=services or [],
                raw_advertisement=advertisement_data or b"",
            )
            if self.location:
                device.latitude, device.longitude, device.accuracy = self.location
            self.devices[address] = device

        # Apply any extra kwargs
        for key, value in kwargs.items():
            if hasattr(device, key) and value is not None:
                setattr(device, key, value)

        self._notify("device", device.to_dict())

    def get_all_devices(self) -> list[dict[str, Any]]:
        """Get all discovered devices as list of dicts."""
        return [d.to_dict() for d in self.devices.values()]

    def get_stats(self) -> dict[str, Any]:
        """Get scanner statistics."""
        return {
            "deviceCount": len(self.devices),
            "packetCount": self.packet_count,
            "running": self.running,
            "location": {
                "latitude": self.location[0] if self.location else None,
                "longitude": self.location[1] if self.location else None,
                "accuracy": self.location[2] if self.location else None,
            },
        }

    def clear(self):
        """Clear all discovered devices."""
        self.devices.clear()
        self.packet_count = 0
        self._notify("clear", {})


class RFPartyRequestHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for the RFParty web UI."""

    scanner: RFPartyScanner | None = None
    static_dir: Path | None = None

    def __init__(self, *args, **kwargs):
        # Set directory to serve static files from
        if self.static_dir:
            kwargs["directory"] = str(self.static_dir)
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args):  # noqa: A002
        """Override to use Python logging."""
        logger.debug(f"HTTP: {format % args}")

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/api/devices":
            self._send_json(self.scanner.get_all_devices() if self.scanner else [])
        elif self.path == "/api/stats":
            self._send_json(self.scanner.get_stats() if self.scanner else {})
        elif self.path == "/api/events":
            self._handle_sse()
        elif self.path == "/" or self.path == "/index.html":
            self._serve_index()
        else:
            super().do_GET()

    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/api/location":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                if self.scanner:
                    self.scanner.set_location(
                        data.get("latitude", 0),
                        data.get("longitude", 0),
                        data.get("accuracy", 100),
                    )
                self._send_json({"status": "ok"})
            except Exception as e:
                self._send_error(400, str(e))
        elif self.path == "/api/clear":
            if self.scanner:
                self.scanner.clear()
            self._send_json({"status": "ok"})
        else:
            self._send_error(404, "Not found")

    def _send_json(self, data: Any):
        """Send JSON response."""
        response = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response)

    def _send_error(self, code: int, message: str):
        """Send error response."""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode("utf-8"))

    def _handle_sse(self):
        """Handle Server-Sent Events for real-time updates."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        # Event queue for this connection
        event_queue: list[tuple[str, Any]] = []
        queue_lock = threading.Lock()

        def on_event(event_type: str, data: Any):
            with queue_lock:
                event_queue.append((event_type, data))

        if self.scanner:
            self.scanner.subscribe(on_event)

        try:
            while True:
                # Check for events
                events_to_send = []
                with queue_lock:
                    events_to_send = event_queue.copy()
                    event_queue.clear()

                for event_type, data in events_to_send:
                    message = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
                    self.wfile.write(message.encode("utf-8"))
                    self.wfile.flush()

                # Send keepalive
                if not events_to_send:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()

                time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if self.scanner:
                self.scanner.unsubscribe(on_event)

    def _serve_index(self):
        """Serve the main index.html page."""
        html = self._generate_index_html()
        response = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response)

    def _generate_index_html(self) -> str:
        """Generate the index HTML page."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RFParty Scanner - RACE Toolkit</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e; 
            color: #eee;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        .header h1 { font-size: 1.4em; font-weight: 600; }
        .header .stats { font-size: 0.9em; opacity: 0.9; }
        .main { display: flex; flex: 1; overflow: hidden; }
        #map { flex: 2; min-height: 300px; }
        .sidebar {
            width: 400px;
            background: #16213e;
            display: flex;
            flex-direction: column;
            border-left: 1px solid #333;
        }
        .search-bar {
            padding: 10px;
            background: #1a1a2e;
            border-bottom: 1px solid #333;
        }
        .search-bar input {
            width: 100%;
            padding: 10px 15px;
            border: none;
            border-radius: 20px;
            background: #0f3460;
            color: #fff;
            font-size: 14px;
        }
        .search-bar input::placeholder { color: #888; }
        .device-list {
            flex: 1;
            overflow-y: auto;
            padding: 10px;
        }
        .device-card {
            background: #0f3460;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.2s;
            border: 1px solid transparent;
        }
        .device-card:hover { 
            background: #1a4a7a; 
            border-color: #667eea;
        }
        .device-card.selected {
            border-color: #667eea;
            background: #1a4a7a;
        }
        .device-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .device-name {
            font-weight: 600;
            color: #fff;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 200px;
        }
        .device-rssi {
            font-size: 0.85em;
            padding: 2px 8px;
            border-radius: 12px;
            background: #333;
        }
        .rssi-strong { background: #27ae60; }
        .rssi-medium { background: #f39c12; }
        .rssi-weak { background: #e74c3c; }
        .device-address {
            font-family: monospace;
            font-size: 0.85em;
            color: #aaa;
            margin-bottom: 6px;
        }
        .device-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            font-size: 0.8em;
        }
        .device-tag {
            background: #333;
            padding: 2px 8px;
            border-radius: 4px;
            color: #bbb;
        }
        .device-tag.apple { background: #555; color: #fff; }
        .device-tag.connectable { background: #27ae60; }
        .device-detail-panel {
            background: #0f3460;
            padding: 15px;
            border-top: 1px solid #333;
            max-height: 40%;
            overflow-y: auto;
        }
        .device-detail-panel h3 {
            margin-bottom: 10px;
            color: #667eea;
        }
        .detail-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #222;
            font-size: 0.9em;
        }
        .detail-label { color: #888; }
        .detail-value { 
            color: #fff; 
            font-family: monospace;
            text-align: right;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .copy-btn {
            background: #667eea;
            border: none;
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
            font-size: 0.9em;
        }
        .copy-btn:hover { background: #764ba2; }
        .status-bar {
            background: #0f3460;
            padding: 8px 15px;
            font-size: 0.85em;
            display: flex;
            justify-content: space-between;
            border-top: 1px solid #333;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }
        .status-dot.active { background: #27ae60; animation: pulse 1.5s infinite; }
        .status-dot.inactive { background: #e74c3c; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .toolbar {
            padding: 10px;
            background: #1a1a2e;
            display: flex;
            gap: 10px;
            border-bottom: 1px solid #333;
        }
        .toolbar button {
            background: #0f3460;
            border: 1px solid #333;
            color: #fff;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
        }
        .toolbar button:hover { background: #1a4a7a; }
        .toolbar button.active { background: #667eea; border-color: #667eea; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎉 RFParty Scanner</h1>
        <div class="stats">
            <span id="device-count">0</span> devices | 
            <span id="packet-count">0</span> packets
        </div>
    </div>
    
    <div class="main">
        <div id="map"></div>
        <div class="sidebar">
            <div class="toolbar">
                <button onclick="clearDevices()">Clear All</button>
                <button onclick="exportJSON()">Export JSON</button>
                <button onclick="exportCSV()">Export CSV</button>
            </div>
            <div class="search-bar">
                <input type="text" id="search" placeholder="Search by name, address, or manufacturer...">
            </div>
            <div class="device-list" id="device-list"></div>
            <div class="device-detail-panel" id="detail-panel" style="display: none;">
                <h3>Device Details</h3>
                <div id="detail-content"></div>
                <button class="copy-btn" onclick="copyDeviceData()">📋 Copy to Clipboard</button>
            </div>
        </div>
    </div>
    
    <div class="status-bar">
        <span><span class="status-dot active" id="status-dot"></span><span id="status-text">Scanning...</span></span>
        <span id="location-text">Location: Unknown</span>
    </div>
    
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        // State
        let devices = {};
        let selectedDevice = null;
        let markers = {};
        let map;
        
        // Initialize map
        function initMap() {
            map = L.map('map', { attributionControl: false }).setView([0, 0], 2);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                maxZoom: 19
            }).addTo(map);
            
            // Try to get user location
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(
                    (pos) => {
                        const { latitude, longitude, accuracy } = pos.coords;
                        map.setView([latitude, longitude], 15);
                        updateLocation(latitude, longitude, accuracy);
                        
                        // Add accuracy circle
                        L.circle([latitude, longitude], {
                            radius: accuracy,
                            color: '#667eea',
                            fillOpacity: 0.1,
                            weight: 2
                        }).addTo(map);
                        
                        // Send location to server
                        fetch('/api/location', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ latitude, longitude, accuracy })
                        });
                    },
                    (err) => console.log('Geolocation error:', err),
                    { enableHighAccuracy: true }
                );
            }
        }
        
        function updateLocation(lat, lon, acc) {
            document.getElementById('location-text').textContent = 
                `Location: ${lat.toFixed(6)}, ${lon.toFixed(6)} (±${acc.toFixed(0)}m)`;
        }
        
        // Connect to SSE for real-time updates
        function connectSSE() {
            const eventSource = new EventSource('/api/events');
            
            eventSource.addEventListener('device', (e) => {
                const device = JSON.parse(e.data);
                devices[device.address] = device;
                updateDeviceList();
                updateMarker(device);
                updateStats();
            });
            
            eventSource.addEventListener('location', (e) => {
                const loc = JSON.parse(e.data);
                updateLocation(loc.latitude, loc.longitude, loc.accuracy);
            });
            
            eventSource.addEventListener('clear', () => {
                devices = {};
                Object.values(markers).forEach(m => map.removeLayer(m));
                markers = {};
                updateDeviceList();
                updateStats();
            });
            
            eventSource.onerror = () => {
                document.getElementById('status-dot').classList.remove('active');
                document.getElementById('status-dot').classList.add('inactive');
                document.getElementById('status-text').textContent = 'Disconnected - Reconnecting...';
                setTimeout(connectSSE, 3000);
            };
            
            eventSource.onopen = () => {
                document.getElementById('status-dot').classList.remove('inactive');
                document.getElementById('status-dot').classList.add('active');
                document.getElementById('status-text').textContent = 'Scanning...';
            };
        }
        
        function updateStats() {
            document.getElementById('device-count').textContent = Object.keys(devices).length;
            const totalPackets = Object.values(devices).reduce((sum, d) => sum + d.packetCount, 0);
            document.getElementById('packet-count').textContent = totalPackets;
        }
        
        function getRssiClass(rssi) {
            if (rssi >= -60) return 'rssi-strong';
            if (rssi >= -80) return 'rssi-medium';
            return 'rssi-weak';
        }
        
        function updateDeviceList() {
            const container = document.getElementById('device-list');
            const searchTerm = document.getElementById('search').value.toLowerCase();
            
            const sortedDevices = Object.values(devices)
                .filter(d => {
                    if (!searchTerm) return true;
                    const searchFields = [
                        d.name || '',
                        d.address,
                        d.manufacturerName || '',
                        ...(d.services || [])
                    ].join(' ').toLowerCase();
                    return searchFields.includes(searchTerm);
                })
                .sort((a, b) => b.rssi - a.rssi);
            
            container.innerHTML = sortedDevices.map(d => `
                <div class="device-card ${selectedDevice === d.address ? 'selected' : ''}" 
                     onclick="selectDevice('${d.address}')">
                    <div class="device-header">
                        <span class="device-name">${d.name || 'Unknown Device'}</span>
                        <span class="device-rssi ${getRssiClass(d.rssi)}">${d.rssi} dBm</span>
                    </div>
                    <div class="device-address">${d.address}</div>
                    <div class="device-meta">
                        ${d.manufacturerName ? `<span class="device-tag">${d.manufacturerName}</span>` : ''}
                        ${d.connectable ? '<span class="device-tag connectable">Connectable</span>' : ''}
                        ${d.appleContinuityType ? `<span class="device-tag apple">${d.appleContinuityType}</span>` : ''}
                        ${d.services?.length ? `<span class="device-tag">${d.services.length} services</span>` : ''}
                        <span class="device-tag">${d.packetCount} pkts</span>
                    </div>
                </div>
            `).join('');
        }
        
        function updateMarker(device) {
            if (!device.latitude || !device.longitude) return;
            
            if (markers[device.address]) {
                markers[device.address].setLatLng([device.latitude, device.longitude]);
            } else {
                const marker = L.circleMarker([device.latitude, device.longitude], {
                    radius: 8,
                    color: device.rssi >= -60 ? '#27ae60' : device.rssi >= -80 ? '#f39c12' : '#e74c3c',
                    fillOpacity: 0.8
                });
                marker.bindPopup(`<b>${device.name || 'Unknown'}</b><br>${device.address}<br>${device.rssi} dBm`);
                marker.addTo(map);
                markers[device.address] = marker;
            }
        }
        
        function selectDevice(address) {
            selectedDevice = address;
            const device = devices[address];
            
            document.getElementById('detail-panel').style.display = 'block';
            document.getElementById('detail-content').innerHTML = `
                <div class="detail-row"><span class="detail-label">Address</span><span class="detail-value">${device.address}</span></div>
                <div class="detail-row"><span class="detail-label">Name</span><span class="detail-value">${device.name || 'Unknown'}</span></div>
                <div class="detail-row"><span class="detail-label">RSSI</span><span class="detail-value">${device.rssi} dBm</span></div>
                <div class="detail-row"><span class="detail-label">Address Type</span><span class="detail-value">${device.addressType}</span></div>
                <div class="detail-row"><span class="detail-label">Connectable</span><span class="detail-value">${device.connectable ? 'Yes' : 'No'}</span></div>
                <div class="detail-row"><span class="detail-label">Manufacturer</span><span class="detail-value">${device.manufacturerName || 'Unknown'} ${device.manufacturerId ? '(0x' + device.manufacturerId.toString(16).padStart(4, '0') + ')' : ''}</span></div>
                <div class="detail-row"><span class="detail-label">Packets</span><span class="detail-value">${device.packetCount}</span></div>
                <div class="detail-row"><span class="detail-label">Duration</span><span class="detail-value">${(device.durationMs / 1000).toFixed(1)}s</span></div>
                ${device.services?.length ? `<div class="detail-row"><span class="detail-label">Services</span><span class="detail-value">${device.services.join(', ')}</span></div>` : ''}
                ${device.rawAdvertisement ? `<div class="detail-row"><span class="detail-label">Raw Data</span><span class="detail-value" style="word-break: break-all; font-size: 0.7em;">${device.rawAdvertisement}</span></div>` : ''}
            `;
            
            updateDeviceList();
            
            if (device.latitude && device.longitude) {
                map.setView([device.latitude, device.longitude], 17);
            }
        }
        
        function copyDeviceData() {
            if (!selectedDevice) return;
            const device = devices[selectedDevice];
            navigator.clipboard.writeText(JSON.stringify(device, null, 2))
                .then(() => alert('Device data copied to clipboard!'))
                .catch(err => console.error('Copy failed:', err));
        }
        
        function clearDevices() {
            if (confirm('Clear all discovered devices?')) {
                fetch('/api/clear', { method: 'POST' });
            }
        }
        
        function exportJSON() {
            const data = JSON.stringify(Object.values(devices), null, 2);
            downloadFile(data, 'rfparty-export.json', 'application/json');
        }
        
        function exportCSV() {
            const headers = ['address', 'name', 'rssi', 'addressType', 'connectable', 'manufacturerName', 'services', 'packetCount', 'firstSeen', 'lastSeen'];
            const rows = Object.values(devices).map(d => 
                headers.map(h => {
                    const val = d[h];
                    if (Array.isArray(val)) return val.join(';');
                    if (typeof val === 'boolean') return val ? 'true' : 'false';
                    return val ?? '';
                }).join(',')
            );
            const csv = [headers.join(','), ...rows].join('\\n');
            downloadFile(csv, 'rfparty-export.csv', 'text/csv');
        }
        
        function downloadFile(content, filename, type) {
            const blob = new Blob([content], { type });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
        }
        
        // Initialize
        document.getElementById('search').addEventListener('input', updateDeviceList);
        initMap();
        connectSSE();
        
        // Load initial devices
        fetch('/api/devices')
            .then(r => r.json())
            .then(data => {
                data.forEach(d => {
                    devices[d.address] = d;
                    updateMarker(d);
                });
                updateDeviceList();
                updateStats();
            });
    </script>
</body>
</html>"""


class RFPartyServer:
    """HTTP server for the RFParty web UI."""

    def __init__(
        self, scanner: RFPartyScanner, port: int = 8888, static_dir: Path | None = None
    ):
        self.scanner = scanner
        self.port = port
        self.static_dir = static_dir or Path(__file__).parent / "static"
        self.server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, open_browser: bool = True):
        """Start the HTTP server in a background thread."""
        # Configure the handler
        RFPartyRequestHandler.scanner = self.scanner
        RFPartyRequestHandler.static_dir = self.static_dir

        self.server = HTTPServer(("0.0.0.0", self.port), RFPartyRequestHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

        url = f"http://localhost:{self.port}"
        logger.info(f"RFParty server started at {url}")

        if open_browser:
            webbrowser.open(url)

    def stop(self):
        """Stop the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
