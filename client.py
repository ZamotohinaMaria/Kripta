import logging
import socket
import ssl
from datetime import datetime
from os import getpid
from pathlib import Path
from time import sleep

SERVER_HOST = "localhost"
SERVER_PORT = 60000
BUFFER_SIZE = 1024
CONNECT_TIMEOUT = 5
SOCKET_TIMEOUT = 10
RECONNECT_DELAY = 2

BASE_DIR = Path(__file__).resolve().parent
CA_FILE = BASE_DIR / "certs" / "server.crt"
LOG_DIR = BASE_DIR / "logs"
LOGGER = logging.getLogger("tls_client")


def create_tls_context() -> ssl.SSLContext:
    if not CA_FILE.exists():
        raise FileNotFoundError("Missing CA certificate: certs/server.crt")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def configure_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = LOG_DIR / f"client_{stamp}_{getpid()}.log"

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


def send_and_receive(connection: ssl.SSLSocket, message: str) -> str:
    LOGGER.debug("Sending: %s", message)
    connection.sendall(message.encode("utf-8"))
    data = connection.recv(BUFFER_SIZE)
    if not data:
        raise ConnectionError("Server closed the connection.")
    response = data.decode("utf-8", errors="replace")
    LOGGER.debug("Received: %s", response)
    return response


def run_client() -> None:
    logger = configure_logging()
    waiting_notice_shown = False

    while True:
        try:
            context = create_tls_context()
            with socket.create_connection(
                (SERVER_HOST, SERVER_PORT), timeout=CONNECT_TIMEOUT
            ) as raw_socket:
                raw_socket.settimeout(SOCKET_TIMEOUT)
                with context.wrap_socket(
                    raw_socket, server_hostname=SERVER_HOST
                ) as connection:
                    waiting_notice_shown = False
                    connection.settimeout(SOCKET_TIMEOUT)
                    logger.info("TLS connection established")
                    logger.info(
                        f"Protocol: {connection.version()}, cipher: {connection.cipher()}"
                    )
                    logger.info(
                        f"Peer cert subject: {connection.getpeercert().get('subject')}"
                    )

                    for i in range(1, 6):
                        message = f"Hello {i}"
                        response = send_and_receive(connection, message)
                        logger.info("Hello exchange %s: %s", i, response)
                        sleep(1)

                    print(f"Connection to {SERVER_HOST}:{SERVER_PORT} established successfully.")
                    while True:
                        try:
                            message = input("> ").strip()
                        except EOFError:
                            logger.info("Input stream closed (EOF). Closing connection.")
                            print("Connection closed.")
                            return
                        except KeyboardInterrupt:
                            logger.info("Client interrupted by user.")
                            print("\nConnection closed.")
                            return

                        if not message:
                            continue
                        if message.lower() in {"exit", "quit"}:
                            logger.info("Client requested connection close.")
                            print("Connection closed.")
                            return

                        response = send_and_receive(connection, message)
                        print(f"Server reply: {response}")
        except (ConnectionError, socket.timeout, OSError, ssl.SSLError) as exc:
            logger.exception("Connection issue, reconnecting in %ss: %s", RECONNECT_DELAY, exc)
            if not waiting_notice_shown:
                print("Waiting for server...")
                waiting_notice_shown = True
            sleep(RECONNECT_DELAY)
        except KeyboardInterrupt:
            logger.info("Client stopped by user.")
            print("\nClient stopped.")
            return


if __name__ == "__main__":
    run_client()
