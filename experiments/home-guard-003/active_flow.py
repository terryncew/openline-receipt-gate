"""TV ignores authorizer and keeps sending over its existing TCP socket.

Shared-FS ready/stop markers only orchestrate the synthetic test, not network
security. Kernel iptables/veth enforcement is independent of this client.
"""
import argparse
import json
from pathlib import Path
import socket
import sys
import time

def emit(event: str, seq: int, *, detail: str = ""):
    print(json.dumps({"t_us": time.time_ns() // 1000,
                      "seq": seq, "event": event, "detail": detail}, sort_keys=True),
          flush=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ready", type=Path, required=True)
    p.add_argument("--stop", type=Path, required=True)
    a = p.parse_args()
    with socket.create_connection(("10.73.2.2",8080), timeout=3) as sock:
        sock.settimeout(0.14)
        emit("CONNECTED",0)
        seq, good = 0, 0
        while not a.stop.exists() and seq < 150:
            seq += 1
            packet = (f"{seq}\n").encode()
            try:
                sock.sendall(packet)
                emit("SENT",seq)
            except OSError as error:
                emit("WRITE_ERROR",seq,detail=type(error).__name__)
                time.sleep(0.12)
                continue
            try:
                response=sock.recv(250)
                if response == b"ACK:"+packet:
                    emit("ACK",seq)
                    good += 1
                    if good >= 5 and not a.ready.exists():
                        a.ready.write_text(str(time.time_ns() // 1000)+"\n")
                elif response:
                    emit("UNEXPECTED_ACK",seq,detail=response.decode(errors="replace"))
                else:
                    emit("EOF",seq)
            except (socket.timeout,TimeoutError):
                emit("NO_ACK",seq)
            except OSError as error:
                emit("READ_ERROR",seq,detail=type(error).__name__)
            time.sleep(0.12)
        emit("EXIT",seq)

if __name__ == "__main__":
    main()
