import argparse
import time
from dataclasses import dataclass
from typing import Any
from scapy.all import IP, TCP, Raw, conf, send, sniff


TLS_CONTENT_TYPES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}

TLS_HANDSHAKE_TYPES = {
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    8: "encrypted_extensions",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
}


@dataclass
class Stats:
    packets_seen: int = 0
    tls_packets_seen: int = 0
    blocked_packets: int = 0
    started_at: float = 0.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "TLS sniffer/blocker for traffic between Alice and Bob VMs. "
            "Run on the parent host with rights for raw packet capture."
        )
    )
    parser.add_argument("--alice-ip", required=True, help="IP address of Alice VM.")
    parser.add_argument("--bob-ip", required=True, help="IP address of Bob VM.")
    parser.add_argument("--port", type=int, default=60000, help="TLS TCP port.")
    parser.add_argument(
        "--iface",
        default=None,
        help=(
            "Network interface name for capture. "
            "If omitted, interface is auto-selected using route to Alice/Bob."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["sniff", "rst"],
        default="sniff",
        help=(
            "sniff: capture only; "
            "rst: terminate matched TCP flows using forged RST packets."
        ),
    )
    parser.add_argument(
        "--no-tls-only",
        action="store_true",
        help="Print all matched TCP packets, not only packets that look like TLS records.",
    )
    return parser.parse_args()


def detect_tls(payload: bytes) -> tuple[bool, str]:
    if len(payload) < 5:
        return False, ""

    content_type = payload[0]
    if content_type not in TLS_CONTENT_TYPES:
        return False, ""

    version_major = payload[1]
    version_minor = payload[2]
    record_len = int.from_bytes(payload[3:5], "big")
    version = f"{version_major}.{version_minor}"
    label = TLS_CONTENT_TYPES[content_type]

    details = f"type={label}, tls_version={version}, record_len={record_len}"

    if content_type == 22 and len(payload) >= 6:
        hs_type = payload[5]
        hs_name = TLS_HANDSHAKE_TYPES.get(hs_type, f"handshake_{hs_type}")
        details += f", handshake={hs_name}"

    return True, details


def send_rst_for_packet(pkt: Any, iface: str | None) -> None:
    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    syn = 1 if tcp.flags & 0x02 else 0
    fin = 1 if tcp.flags & 0x01 else 0
    payload_len = len(bytes(tcp.payload))
    next_seq = tcp.seq + payload_len + syn + fin

    rst_to_dst = IP(src=ip.src, dst=ip.dst) / TCP(
        sport=tcp.sport,
        dport=tcp.dport,
        flags="R",
        seq=next_seq,
    )
    rst_to_src = IP(src=ip.dst, dst=ip.src) / TCP(
        sport=tcp.dport,
        dport=tcp.sport,
        flags="R",
        seq=tcp.ack,
    )

    send(rst_to_dst, iface=iface, verbose=False, count=2)
    send(rst_to_src, iface=iface, verbose=False, count=2)


def build_filter(alice_ip: str, bob_ip: str, port: int) -> str:
    return f"tcp and host {alice_ip} and host {bob_ip} and port {port}"


def resolve_capture_ifaces(
    iface_arg: str | None, alice_ip: str, bob_ip: str
) -> str | list[str]:
    if iface_arg:
        return iface_arg

    route_ifaces: list[str] = []
    for peer_ip in (alice_ip, bob_ip):
        try:
            route = conf.route.route(peer_ip)
            iface_name = str(route[0])
            if iface_name and iface_name not in route_ifaces:
                route_ifaces.append(iface_name)
        except Exception:
            continue

    if route_ifaces:
        if len(route_ifaces) == 1:
            return route_ifaces[0]
        return route_ifaces

    return conf.iface


def main() -> None:
    args = parse_args()
    stats = Stats(started_at=time.time())

    iface = resolve_capture_ifaces(args.iface, args.alice_ip, args.bob_ip)
    bpf_filter = build_filter(args.alice_ip, args.bob_ip, args.port)
    tls_only = not args.no_tls_only
    block_mode = args.mode

    print(f"Interface: {iface}")
    print(f"BPF filter: {bpf_filter}")
    print(f"Mode: {block_mode}")
    print("Press Ctrl+C to stop.")

    def on_packet(pkt: Any) -> None:
        nonlocal stats

        if IP not in pkt or TCP not in pkt:
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        stats.packets_seen += 1

        payload = b""
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)

        is_tls, tls_info = detect_tls(payload)
        if tls_only and not is_tls:
            return

        direction = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        flags = str(tcp.flags)
        if is_tls:
            stats.tls_packets_seen += 1
            print(f"\n[TLS] {direction} | flags={flags} | {tls_info}")
        else:
            print(f"\n[TCP] {direction} | flags={flags} | payload_len={len(payload)}")

        if block_mode == "rst":
            send_rst_for_packet(pkt, args.iface)
            stats.blocked_packets += 1
            print(f"\n[BLOCK] Sent TCP RST packets for flow {direction}")

    try:
        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=on_packet,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Start terminal as Administrator/root.")
        raise
    except KeyboardInterrupt:
        pass
    finally:
        elapsed = max(0.001, time.time() - stats.started_at)
        print("\nStopped.")
        print(f"Packets seen: {stats.packets_seen}")
        print(f"TLS packets: {stats.tls_packets_seen}")
        print(f"Blocked packets: {stats.blocked_packets}")
        print(f"Runtime: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
