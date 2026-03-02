import logging
import signal
import socket
import ssl
import subprocess
from os import environ
from datetime import datetime
from pathlib import Path
from shutil import which
from threading import Event

HOST = "127.0.0.1"
PORT = 60000
BUFFER_SIZE = 1024
SERVER_POLL_TIMEOUT = 1.0
CLIENT_POLL_TIMEOUT = 1.0

BASE_DIR = Path(__file__).resolve().parent
CERT_FILE = BASE_DIR / "certs" / "server.crt"
KEY_FILE = BASE_DIR / "certs" / "server.key"
LOG_DIR = BASE_DIR / "logs"
LOGGER = logging.getLogger("tls_server")
SHUTDOWN_REQUESTED = Event()


def configure_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "server.log"

    LOGGER.setLevel(logging.DEBUG)
    LOGGER.propagate = False
    LOGGER.handlers.clear()

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    LOGGER.addHandler(file_handler)
    return LOGGER


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


def generate_server_certificate() -> None:
    openssl_bin = which("openssl")
    if not openssl_bin:
        raise RuntimeError("OpenSSL is not installed or not in PATH.")

    CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    env = dict(environ)
    openssl_cnf = env.get("OPENSSL_CONF")
    if not openssl_cnf or not Path(openssl_cnf).exists():
        discovered_cnf = find_openssl_cnf()
        if discovered_cnf is not None:
            env["OPENSSL_CONF"] = str(discovered_cnf)
            openssl_cnf = str(discovered_cnf)

    command = [
        openssl_bin,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-keyout",
        str(KEY_FILE),
        "-out",
        str(CERT_FILE),
        "-days",
        "365",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    if openssl_cnf:
        command.extend(["-config", openssl_cnf])

    result = subprocess.run(command, check=True, env=env, capture_output=True, text=True)
    LOGGER.debug("Certificate generated at %s", datetime.now().isoformat(timespec="seconds"))
    if result.stderr.strip():
        LOGGER.debug("OpenSSL stderr: %s", result.stderr.strip())


def create_tls_context() -> ssl.SSLContext:
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        raise FileNotFoundError(
            "Missing TLS files. Expected: certs/server.crt and certs/server.key"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    return context


def request_shutdown(signum: int, _frame: object) -> None:
    if SHUTDOWN_REQUESTED.is_set():
        return
    SHUTDOWN_REQUESTED.set()
    LOGGER.info("Shutdown signal received: %s", signum)
    print("Stopping server...")


def install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_shutdown)


def run_server() -> None:
    logger = configure_logging()
    SHUTDOWN_REQUESTED.clear()
    install_signal_handlers()
    generate_server_certificate()
    context = create_tls_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(SERVER_POLL_TIMEOUT)
        server.bind((HOST, PORT))
        server.listen(5)
        logger.info("TLS server started on %s:%s", HOST, PORT)
        print(f"Server started: {HOST}:{PORT}")

        while not SHUTDOWN_REQUESTED.is_set():
            try:
                raw_connection, client_address = server.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                request_shutdown(signal.SIGINT, None)
                continue
            except OSError as exc:
                if SHUTDOWN_REQUESTED.is_set():
                    break
                logger.exception("Accept failed: %s", exc)
                continue

            raw_connection.settimeout(CLIENT_POLL_TIMEOUT)
            try:
                with context.wrap_socket(
                    raw_connection, server_side=True
                ) as connection:
                    connection.settimeout(CLIENT_POLL_TIMEOUT)
                    logger.info("TLS established with %s", client_address)
                    logger.info(
                        "Protocol: %s, cipher: %s",
                        connection.version(),
                        connection.cipher(),
                    )
                    print(f"Client connected: {client_address[0]}:{client_address[1]}")

                    while not SHUTDOWN_REQUESTED.is_set():
                        try:
                            data = connection.recv(BUFFER_SIZE)
                        except socket.timeout:
                            continue
                        except KeyboardInterrupt:
                            request_shutdown(signal.SIGINT, None)
                            break
                        except OSError as exc:
                            logger.exception("Socket error from %s: %s", client_address, exc)
                            break

                        if not data:
                            logger.info("Client disconnected: %s", client_address)
                            break
                        message = data.decode("utf-8", errors="replace")
                        logger.info("Received from %s: %s", client_address, message)
                        print(f"Message from {client_address[0]}:{client_address[1]}: {message}")
                        connection.sendall(f"ACK: {message}".encode("utf-8"))
            except ssl.SSLError as exc:
                raw_connection.close()
                if SHUTDOWN_REQUESTED.is_set():
                    logger.info("TLS connection closed during shutdown.")
                else:
                    logger.exception("TLS error from %s: %s", client_address, exc)
            except OSError as exc:
                raw_connection.close()
                if SHUTDOWN_REQUESTED.is_set():
                    logger.info("Socket closed during shutdown.")
                else:
                    logger.exception("Socket error from %s: %s", client_address, exc)
            except KeyboardInterrupt:
                request_shutdown(signal.SIGINT, None)

    logger.info("Server socket closed.")
    print("Server stopped.")


if __name__ == "__main__":
    run_server()
