import argparse
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from shutil import which

DEFAULT_PORT = 60000
CONNECT_TIMEOUT = 10
MAX_PACKET_SIZE = 64 * 1024


def prompt_with_default(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def ask_mode_interactive() -> str:
    while True:
        value = input("Mode (host/connect): ").strip().lower()
        if value in {"host", "connect"}:
            return value
        print("Please enter 'host' or 'connect'.")


def ask_username() -> str:
    while True:
        value = input("Your name (Alice/Bob): ").strip()
        if value:
            return value
        print("Name cannot be empty.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TLS/SSL P2P program for two apps on different devices."
    )
    parser.add_argument("mode", nargs="?", choices=["host", "connect"])
    parser.add_argument("--bind", help="Local bind IP for host mode.")
    parser.add_argument("--host", help="Remote host IP/DNS for connect mode.")
    parser.add_argument("--port", type=int, help="Port for host/connect.")
    parser.add_argument(
        "--cert",
        default="certs/server.crt",
        help="Path to server certificate for host mode.",
    )
    parser.add_argument(
        "--key",
        default="certs/server.key",
        help="Path to server private key for host mode.",
    )
    parser.add_argument(
        "--cafile",
        default="certs/server.crt",
        help="Path to trusted CA/certificate for connect mode.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable certificate verification in connect mode.",
    )
    return parser.parse_args()


def send_packet(connection: ssl.SSLSocket, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_PACKET_SIZE:
        raise ValueError("Packet is too large.")
    header = struct.pack("!I", len(raw))
    connection.sendall(header + raw)


def recv_exact(connection: ssl.SSLSocket, size: int) -> bytes | None:
    chunks: list[bytes] = []
    bytes_left = size
    while bytes_left > 0:
        chunk = connection.recv(bytes_left)
        if not chunk:
            return None
        chunks.append(chunk)
        bytes_left -= len(chunk)
    return b"".join(chunks)


def recv_packet(connection: ssl.SSLSocket) -> dict | None:
    header = recv_exact(connection, 4)
    if header is None:
        return None
    (size,) = struct.unpack("!I", header)
    if size <= 0 or size > MAX_PACKET_SIZE:
        raise ValueError("Invalid packet size.")

    payload = recv_exact(connection, size)
    if payload is None:
        return None
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Packet must be a JSON object.")
    return data


def create_server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate not found: {cert_path}")
    if not key_path.exists():
        raise FileNotFoundError(f"Private key not found: {key_path}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def find_openssl_cnf() -> Path | None:
    candidates = [
        Path(r"C:\Program Files\Git\usr\ssl\openssl.cnf"),
        Path(r"C:\Program Files\Git\mingw64\ssl\openssl.cnf"),
        Path(r"C:\Program Files\Common Files\ssl\openssl.cnf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    openssl_bin = which("openssl")
    if not openssl_bin:
        raise RuntimeError(
            "OpenSSL not found in PATH. Install OpenSSL or create cert/key manually."
        )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        openssl_bin,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "365",
        "-subj",
        "/CN=p2p-host",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]

    env = None
    openssl_cnf = find_openssl_cnf()
    if openssl_cnf is not None:
        env = dict(os.environ)
        env["OPENSSL_CONF"] = str(openssl_cnf)
        command.extend(["-config", str(openssl_cnf)])

    subprocess.run(command, check=True, capture_output=True, text=True, env=env)


def ensure_server_certificate(cert_path: Path, key_path: Path) -> None:
    cert_exists = cert_path.exists()
    key_exists = key_path.exists()
    if cert_exists and key_exists:
        return

    if cert_exists != key_exists:
        print("Certificate/key pair is incomplete. Regenerating both files...")
        cert_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
    else:
        print("TLS certificate files are missing. Generating self-signed certificate...")

    generate_self_signed_cert(cert_path, key_path)
    print(f"Generated certificate: {cert_path}")
    print(f"Generated private key: {key_path}")


def create_client_context(cafile_path: Path | None, insecure: bool) -> ssl.SSLContext:
    if insecure:
        context = ssl._create_unverified_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    if cafile_path is None or not cafile_path.exists():
        raise FileNotFoundError(
            "Trusted certificate file is required in secure mode. "
            "Use --cafile <path> or start with --insecure."
        )

    context = ssl.create_default_context(cafile=str(cafile_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Useful for labs with self-signed certs and IP-based connection.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def exchange_names_as_host(connection: ssl.SSLSocket, my_name: str) -> str:
    hello = recv_packet(connection)
    if hello is None:
        raise ConnectionError("Peer disconnected before name exchange.")
    if hello.get("type") != "hello" or not isinstance(hello.get("name"), str):
        raise ValueError("Invalid hello packet from peer.")

    peer_name = hello["name"].strip()
    if not peer_name:
        raise ValueError("Peer name is empty.")

    send_packet(connection, {"type": "hello", "name": my_name})
    return peer_name


def exchange_names_as_client(connection: ssl.SSLSocket, my_name: str) -> str:
    send_packet(connection, {"type": "hello", "name": my_name})
    hello = recv_packet(connection)
    if hello is None:
        raise ConnectionError("Peer disconnected before name exchange.")
    if hello.get("type") != "hello" or not isinstance(hello.get("name"), str):
        raise ValueError("Invalid hello packet from peer.")

    peer_name = hello["name"].strip()
    if not peer_name:
        raise ValueError("Peer name is empty.")
    return peer_name


def receive_loop(connection: ssl.SSLSocket, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            packet = recv_packet(connection)
        except socket.timeout:
            continue
        except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"\nConnection closed: {exc}")
            break

        if packet is None:
            print("\nPeer disconnected.")
            break

        packet_type = packet.get("type")
        if packet_type == "message":
            name = str(packet.get("name", "Peer"))
            text = str(packet.get("text", ""))
            sent_at = str(packet.get("time", ""))
            if sent_at:
                print(f"\n[{sent_at}] {name}: {text}")
            else:
                print(f"\n{name}: {text}")
            continue

        if packet_type == "exit":
            name = str(packet.get("name", "Peer"))
            print(f"\n{name} left the chat.")
            break

        print(f"\nReceived unknown packet type: {packet_type}")

    stop_event.set()


def chat(connection: ssl.SSLSocket, my_name: str, peer_name: str) -> None:
    stop_event = threading.Event()
    exit_sent = False
    receiver = threading.Thread(
        target=receive_loop, args=(connection, stop_event), daemon=True
    )
    receiver.start()

    print(f"TLS channel is active. You are '{my_name}', peer is '{peer_name}'.")
    print("Type '/exit' to close connection.")
    try:
        while not stop_event.is_set():
            try:
                message = input(f"{my_name}> ").strip()
            except EOFError:
                break

            if not message:
                continue
            if message == "/exit":
                send_packet(connection, {"type": "exit", "name": my_name})
                exit_sent = True
                break

            try:
                send_packet(
                    connection,
                    {
                        "type": "message",
                        "name": my_name,
                        "text": message,
                        "time": datetime.now().strftime("%H:%M:%S"),
                    },
                )
            except (ConnectionError, OSError, ValueError) as exc:
                print(f"Connection closed while sending: {exc}")
                break
    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        if not exit_sent:
            try:
                send_packet(connection, {"type": "exit", "name": my_name})
            except (ConnectionError, OSError, ValueError):
                pass
        stop_event.set()
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def run_host(bind_ip: str, port: int, cert: Path, key: Path, my_name: str) -> None:
    ensure_server_certificate(cert, key)
    context = create_server_context(cert, key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_ip, port))
        listener.listen(1)
        print(f"Listening on {bind_ip}:{port}")
        print("Waiting for peer...")

        raw_socket, addr = listener.accept()
        with raw_socket:
            with context.wrap_socket(raw_socket, server_side=True) as tls_socket:
                print(f"Peer connected: {addr[0]}:{addr[1]}")
                print(
                    f"TLS established: protocol={tls_socket.version()}, "
                    f"cipher={tls_socket.cipher()[0]}"
                )
                peer_name = exchange_names_as_host(tls_socket, my_name)
                print(f"Name exchange complete: peer is '{peer_name}'.")
                chat(tls_socket, my_name=my_name, peer_name=peer_name)


def run_connect(
    host: str, port: int, cafile: Path | None, insecure: bool, my_name: str
) -> None:
    if host == "0.0.0.0":
        raise ValueError(
            "Invalid --host value '0.0.0.0'. "
            "Use server IP (for example 192.168.x.x) or 127.0.0.1 for local tests."
        )

    context = create_client_context(cafile, insecure)
    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw_socket:
        raw_socket.settimeout(None)
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            tls_socket.settimeout(None)
            print(f"Connected to {host}:{port}")
            print(
                f"TLS established: protocol={tls_socket.version()}, "
                f"cipher={tls_socket.cipher()[0]}"
            )
            if not insecure:
                print("Certificate verification: ON")
            else:
                print("Certificate verification: OFF (--insecure)")
            peer_name = exchange_names_as_client(tls_socket, my_name)
            print(f"Name exchange complete: peer is '{peer_name}'.")
            chat(tls_socket, my_name=my_name, peer_name=peer_name)


def main() -> None:
    try:
        args = parse_args()
        my_name = ask_username()

        mode = args.mode or ask_mode_interactive()
        port = args.port or int(prompt_with_default("Port", str(DEFAULT_PORT)))

        if mode == "host":
            bind_ip = args.bind or prompt_with_default(
                "Bind address (host IP)", "0.0.0.0"
            )
            cert = Path(args.cert)
            key = Path(args.key)
            run_host(bind_ip=bind_ip, port=port, cert=cert, key=key, my_name=my_name)
            return

        host = args.host or prompt_with_default("Remote host IP/DNS", "127.0.0.1")
        cafile = None if args.insecure else Path(args.cafile)
        run_connect(
            host=host,
            port=port,
            cafile=cafile,
            insecure=args.insecure,
            my_name=my_name,
        )
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as exc:
        print(f"Error: {exc}")


if __name__ == "__main__":
    main()
