"""Always-responsive synthetic endpoints with NO built-in policy checks."""
import argparse
import socket
import threading

def handle(conn, address, role):
    with conn:
        conn.settimeout(15)
        while True:
            try:
                chunk = conn.recv(256)
            except (OSError, TimeoutError):
                return
            if not chunk:
                return
            if role == "nvr":
                response = b"ACK:" + chunk
            else:
                response = b"OK:hvac"
            try:
                conn.sendall(response)
            except OSError:
                return

def main():
    a = argparse.ArgumentParser()
    a.add_argument("--role", choices=["nvr", "hvac"], required=True)
    a.add_argument("--bind", required=True)
    a.add_argument("--port", type=int, required=True)
    args = a.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.bind, args.port))
        sock.listen(16)
        print(f"READY role={args.role} at={args.bind}:{args.port}", flush=True)
        while True:
            conn, address = sock.accept()
            threading.Thread(target=handle, args=(conn,address,args.role), daemon=True).start()

if __name__ == "__main__":
    main()
