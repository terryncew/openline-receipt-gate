"""Synthetic TCP endpoints and an intentionally forwarding relay, never real devices."""
import argparse
import socket
import threading

def handle(sock, address, role, target):
    with sock:
        sock.settimeout(3)
        try:
            payload = sock.recv(200)
            if not payload:
                return
            if role == "relay":
                try:
                    with socket.create_connection(target, timeout=1.5) as downstream:
                        downstream.sendall(b"relay-forward-test")
                        reply = downstream.recv(200)
                        response = b"RELAY_REACHED_PROTECTED:" + reply
                except (OSError, TimeoutError):
                    response = b"RELAY_DOWNSTREAM_BLOCKED"
            else:
                response = ("OK:" + role).encode()
            sock.sendall(response)
            print(f"ROLE={role} FROM={address[0]}:{address[1]} RESPONSE={response!r}", flush=True)
        except (OSError, TimeoutError) as error:
            print(f"ROLE={role} ERROR={type(error).__name__}", flush=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=["nvr", "hvac", "relay"])
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, action="append", required=True)
    a = parser.parse_args()
    ports = list(dict.fromkeys(a.port))
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.bind, port))
        s.listen(16)
        def serve(server):
            with server:
                while True:
                    client, address = server.accept()
                    threading.Thread(target=handle, args=(client, address, a.role, ("10.73.2.2", 8080)),
                                     daemon=True).start()
        threading.Thread(target=serve, args=(s,), daemon=True).start()
        print(f"READY role={a.role} bind={a.bind}:{port}", flush=True)
    threading.Event().wait()

if __name__ == "__main__":
    main()
