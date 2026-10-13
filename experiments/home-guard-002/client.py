"""Attempts run inside disposable namespaces; stdout is not proof of filtering."""
import argparse
import json
import socket
import struct


def checksum(buf):
    if len(buf) % 2:
        buf += b"\x00"
    total = sum((buf[i] << 8) + buf[i + 1] for i in range(0, len(buf), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def spoof(src, dst, port):
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    # Real raw IP packet, forged L3 source, TCP SYN with a valid checksum.
    tcp = struct.pack("!HHLLBBHHH", 42424, port, 0x14c2026, 0, 5 << 4, 2, 4096, 0, 0)
    pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    tcp_sum = checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x2026, 0, 60,
                     socket.IPPROTO_TCP, 0, src_bytes, dst_bytes)
    ip_sum = checksum(ip)
    ip = ip[:10] + struct.pack("!H", ip_sum) + ip[12:]
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.sendto(ip + tcp, (dst, port))
    print(json.dumps({"label": "tv-spoofed-thermostat", "src": src, "dst": dst,
                      "dst_port": port, "source_port": 42424, "status": "RAW_SYN_SENT"},
                     sort_keys=True))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--label", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--expect", choices=["drop", "ok-hvac", "relay-blocked", "raw-spoof"], required=True)
    args = p.parse_args()
    if args.expect == "raw-spoof":
        spoof("10.73.3.2", args.host, args.port)
        return
    status, response = None, ""
    try:
        with socket.create_connection((args.host, args.port), timeout=1.35) as sock:
            sock.settimeout(2.5)
            sock.sendall(b"synthetic-client-probe")
            response = sock.recv(250).decode("utf-8", errors="replace")
            status = "CONNECTED"
    except socket.timeout:
        status = "TIMEOUT"
    except OSError as exc:
        status = "ERROR:" + type(exc).__name__
    actual = status == "TIMEOUT" if args.expect == "drop" else (
        status == "CONNECTED" and
        (response == "OK:hvac" if args.expect == "ok-hvac"
         else response == "RELAY_DOWNSTREAM_BLOCKED"))
    print(json.dumps({"label": args.label, "host": args.host, "port": args.port,
                      "status": status, "response": response, "expected": args.expect,
                      "pass": actual}, sort_keys=True))
    if not actual:
        raise SystemExit(f"FALSIFIER: {args.label} expected {args.expect} got {status} {response}")


if __name__ == "__main__":
    main()
