import argparse
import ipaddress
import logging

from scapy.all import (  # type: ignore
    ICMP,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    TCP,
    sr1,
)
from scapy.error import Scapy_Exception  # type: ignore

logger = logging.getLogger(__name__)


def banner():
    print(
        r"""
      ____  ____  ___  ____  ____  ____
     / ___||  _ \|_ _|/ ___||  _ \|  _ \
     \___ \| |_) || | \___ \| |_) | |_) |
      ___) |  __/ | |  ___) |  __/|  __/
     |____/|_|   |___||____/|_|   |_|
    """
    )


def main_banner():
    banner()
    print("=" * 58)
    print(" NETWORK PROBE UTILITY | by yuli")
    print("=" * 58)
    print("  Single-host TCP SYN and ICMP/ICMPv6 diagnostics")
    print("  Use only on systems you own or are authorized to test.\n")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Send a TCP SYN or ICMP probe to an IP address."
    )
    parser.add_argument("target_ip", help="destination IPv4 or IPv6 address")
    parser.add_argument(
        "mode",
        nargs="?",
        type=str.lower,
        choices=("tcp", "icmp", "traceroute", "menu"),
        default="menu",
        help="probe mode (default: menu; traceroute currently sends one ICMP probe)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the confirmation prompt for a direct tcp, icmp, or traceroute mode",
    )
    return parser


def confirm_send() -> bool:
    while True:
        try:
            answer = input("Send packet? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print("Input closed; action cancelled.")
            return False

        if answer in ("y", "n"):
            return answer == "y"
        print("Invalid input! Please enter 'y' or 'n'.")


def build_packet(target_ip: str, protocol: str):
    address = ipaddress.ip_address(target_ip)
    network_layer = IP if address.version == 4 else IPv6

    if protocol == "tcp":
        return network_layer(dst=str(address)) / TCP(dport=80, flags="S")
    if protocol == "icmp":
        transport_layer = ICMP if address.version == 4 else ICMPv6EchoRequest
        return network_layer(dst=str(address)) / transport_layer()
    raise ValueError(f"Unsupported protocol: {protocol}")


def handle_response(target_ip: str, response):
    if not response:
        logger.warning("No response received from %s within timeout window.", target_ip)
        return

    if response.haslayer(ICMP) or response.haslayer(ICMPv6EchoReply):
        response_type = "ICMP"
    elif response.haslayer(TCP):
        response_type = "TCP"
    else:
        response_type = "unexpected"

    logger.info("Received %s response from %s:", response_type, target_ip)
    logger.info(response.summary())


def send_packet(target_ip: str, protocol: str) -> bool:
    try:
        packet = build_packet(target_ip, protocol)
        if protocol == "tcp":
            logger.info("Sending TCP SYN packet to %s on port 80...", target_ip)
        else:
            logger.info("Sending ICMP packet to %s...", target_ip)

        response = sr1(packet, timeout=2, verbose=False)
    except (OSError, Scapy_Exception) as exc:
        logger.error("Packet send failed: %s", exc)
        return False

    handle_response(target_ip, response)
    return True


def send_packet_interactive(target_ip: str) -> bool:
    print("\n  SELECT A PROBE")
    print("  [1] TCP SYN to port 80")
    print("  [2] ICMP / ICMPv6 echo request")
    print("  [q] Quit")

    while True:
        try:
            choice = input("  Choice [1/2/q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print("Input closed; returning to the command prompt.")
            return True

        if choice == "q":
            return True
        if choice not in ("1", "2"):
            print("Invalid choice. Enter 1, 2, or q.")
            continue
        break

    if not confirm_send():
        print("Action cancelled by user.")
        return True

    return send_packet(target_ip, "tcp" if choice == "1" else "icmp")


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        target_ip = str(ipaddress.ip_address(args.target_ip))
    except ValueError:
        parser.error("target_ip must be a valid IPv4 or IPv6 address")

    logger.info("Target IP: %s", target_ip)

    if args.mode == "menu":
        main_banner()
        return 0 if send_packet_interactive(target_ip) else 1

    if not args.yes and not confirm_send():
        print("Action cancelled by user.")
        return 0

    if args.mode == "traceroute":
        logger.info(
            "Traceroute mode currently sends one ICMP probe; it does not trace hops."
        )
        success = send_packet(target_ip, "icmp")
    else:
        success = send_packet(target_ip, args.mode)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
