"""Generate two synthetic offline HTTP captures. No network traffic is sent."""

import socket
import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(reverse: bool, sequence: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    client, server = socket.inet_aton("192.0.2.10"), socket.inet_aton("198.51.100.20")
    src, dst = (server, client) if reverse else (client, server)
    sport, dport = (80, 42000) if reverse else (42000, 80)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, sequence, ack, 80, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 69, 0, 40 + len(payload), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + tcp + payload


def capture(path: Path, suspicious: bool = True) -> Path:
    uri = "/../../etc/passwd" if suspicious else "/index.html"
    request = f"GET {uri} HTTP/1.1\r\nHost: demo.invalid\r\nConnection: close\r\n\r\n".encode()
    response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDenied"
    frames = [
        packet(False, 100, 0, 2),
        packet(True, 200, 101, 18),
        packet(False, 101, 201, 16),
        packet(False, 101, 201, 24, request),
        packet(True, 201, 101 + len(request), 24, response),
        packet(False, 101 + len(request), 201 + len(response), 17),
        packet(True, 201 + len(response), 102 + len(request), 17),
    ]
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            stream.write(struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)))
            stream.write(frame)
    return path


if __name__ == "__main__":
    for filename, suspicious in (("traversal.pcap", True), ("benign.pcap", False)):
        result = capture(Path(__file__).resolve().parent / filename, suspicious)
        print(result)
