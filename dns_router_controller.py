#!/usr/bin/env python3
"""
DNS Router Controller - Redirección DNS transparente
Captura y redirige queries DNS, permite IPs resueltas, bloquea lo demás.
"""

import os
import sys
import argparse
import threading
import time
import socket
import struct
import subprocess
import logging
import re
from collections import defaultdict
from ipaddress import ip_address, ip_network

try:
    from scapy.all import sniff, IP, UDP, DNS, DNSRR, Raw
except ImportError:
    print("Error: scapy required. Install: pip install scapy")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BlacklistManager:
    def __init__(self):
        self.blacklisted_domains = set()
        self.whitelisted_domains = set()
        self.lock = threading.Lock()

    def load_from_file(self, filepath):
        if not os.path.exists(filepath):
            logger.warning(f"Blacklist file not found: {filepath}")
            return 0

        count = 0
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("!"):
                    domain = line[1:].strip().lower()
                    if domain:
                        self.whitelisted_domains.add(domain)
                        count += 1
                else:
                    domain = line.lower()
                    if domain:
                        self.blacklisted_domains.add(domain)
                        count += 1

        logger.info(f"Loaded {count} entries from {filepath}")
        return count

    def is_blacklisted(self, domain):
        domain_lower = domain.lower()
        with self.lock:
            if domain_lower in self.whitelisted_domains:
                return False

            for blocked in self.blacklisted_domains:
                if blocked.startswith("*."):
                    suffix = blocked[2:]
                    if domain_lower.endswith(suffix) or domain_lower == suffix:
                        return True
                elif domain_lower == blocked or domain_lower.endswith("." + blocked):
                    return True

            return False


PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
]

DNS_SERVERS = ["208.67.222.222", "208.67.220.220"]
LISTEN_PORT = 5353
IPSET_NAME = "dns_allowed"
IPSET_TIMEOUT = 3600

resolved_ips = set()
lock = threading.Lock()
blacklist_manager = None


def run_cmd(cmd, check=False):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        if check and result.returncode != 0:
            logger.warning(f"Command failed: {cmd} -> {result.stderr}")
        return result
    except Exception as e:
        logger.warning(f"Command error: {e}")
        return None


def setup_ipset(dns_servers):
    run_cmd(f"ipset create {IPSET_NAME} hash:ip timeout {IPSET_TIMEOUT} -exist")
    for dns in dns_servers:
        run_cmd(f"ipset add {IPSET_NAME} {dns} timeout {IPSET_TIMEOUT} -exist")
    logger.info(f"ipset '{IPSET_NAME}' ready with DNS servers")


def add_to_ipset(ip_str):
    with lock:
        if ip_str not in resolved_ips:
            resolved_ips.add(ip_str)
    run_cmd(f"ipset add {IPSET_NAME} {ip_str} timeout {IPSET_TIMEOUT} -exist")


def is_private_ip(ip_str):
    try:
        ip = ip_address(ip_str)
        for network in PRIVATE_NETWORKS:
            if ip in network:
                return True
    except:
        pass
    return False


def parse_dns_query(data):
    """Extraer dominio de query DNS"""
    try:
        if len(data) < 12:
            return None
        transaction_id = data[:2]
        flags = data[2:4]
        qdcount = struct.unpack("!H", data[4:6])[0]

        if qdcount == 0:
            return None

        offset = 12
        domain_parts = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            domain_parts.append(data[offset + 1 : offset + 1 + length].decode())
            offset += 1 + length

        if domain_parts:
            return ".".join(domain_parts)
    except:
        pass
    return None


def forward_dns_query(domain, dns_server):
    """Reenviar query DNS y obtener respuesta"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        transaction_id = os.urandom(2)
        flags = b"\x01\x00"
        qdcount = b"\x00\x01"
        ancnt = b"\x00\x00"
        nscnt = b"\x00\x00"
        arcnt = b"\x00\x00"

        domain_bytes = b""
        for part in domain.split("."):
            if part:
                domain_bytes += bytes([len(part)]) + part.encode()
        domain_bytes += b"\x00"

        qtype = b"\x00\x01"
        qclass = b"\x00\x01"

        query = (
            transaction_id
            + flags
            + qdcount
            + ancnt
            + nscnt
            + arcnt
            + domain_bytes
            + qtype
            + qclass
        )

        logger.debug(f"Forwarding {domain} to {dns_server}")

        sock.sendto(query, (dns_server, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()

        logger.debug(f"Received {len(response)} bytes from {dns_server}")
        return response
    except socket.timeout:
        logger.warning(f"DNS timeout for {domain} -> {dns_server}")
        return None
    except Exception as e:
        logger.warning(f"DNS forward error for {domain}: {e}")
        return None


def extract_ips_from_response(data):
    """Extraer IPs de respuesta DNS"""
    ips = []
    try:
        if len(data) < 12:
            return ips

        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return ips

        offset = 12

        while offset < len(data):
            try:
                if offset >= len(data):
                    break
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length >= 192:
                    offset += 2
                else:
                    offset += 1 + length
                    if offset + 4 > len(data):
                        break
                    qtype = struct.unpack("!H", data[offset : offset + 2])[0]
                    qclass = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                    offset += 4

                    if offset + 2 > len(data):
                        break
                    rdlength = struct.unpack("!H", data[offset : offset + 2])[0]
                    offset += 2

                    if offset + rdlength > len(data):
                        break

                    if qtype == 1 and rdlength == 4:
                        ip_bytes = data[offset : offset + 4]
                        ip = ".".join(str(b) for b in ip_bytes)
                        ips.append(ip)
                    elif qtype == 28 and rdlength == 16:
                        pass

                    offset += rdlength
            except Exception as e:
                logger.debug(f"Parse error: {e}")
                break
    except Exception as e:
        logger.debug(f"Extract error: {e}")
        pass
    return ips


def handle_dns_query(data, client_addr, blacklist=None):
    """Procesar query DNS, reenviar y responder"""
    domain = parse_dns_query(data)
    if not domain:
        return None

    logger.info(f"[DNS] {client_addr[0]} -> {domain}")

    if blacklist and blacklist.is_blacklisted(domain):
        logger.info(f"[BLACKLISTED] {domain} - blocked by blacklist")
        return None

    for dns_server in DNS_SERVERS:
        response = forward_dns_query(domain, dns_server)
        if response:
            ips = extract_ips_from_response(response)
            logger.info(f"[DNS] {domain} -> {ips}")
            for ip in ips:
                if not is_private_ip(ip) and ip not in ["0.0.0.0", "127.0.0.1"]:
                    add_to_ipset(ip)
                    logger.info(f"[ALLOWED] {ip}")

            return response

    logger.warning(f"[DNS] Failed to resolve: {domain}")
    return None


def dns_server_thread():
    """Servidor DNS proxy"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("", LISTEN_PORT))
        logger.info(f"DNS proxy listening on port {LISTEN_PORT}")
    except OSError as e:
        logger.error(f"Cannot bind port {LISTEN_PORT}: {e}")
        return

    while True:
        try:
            data, client_addr = sock.recvfrom(4096)
            logger.info(f"[PROXY] Received {len(data)} bytes from {client_addr}")
            response = handle_dns_query(data, client_addr, blacklist_manager)
            if response:
                sock.sendto(response, client_addr)
                logger.info(f"[PROXY] Sent response to {client_addr}")
            else:
                logger.warning(f"[PROXY] No response for {client_addr}")
        except Exception as e:
            logger.error(f"DNS server error: {e}")


def capture_dns_packets(interface):
    """Capturar tráfico DNS para logging y ipset"""
    logger.info(f"Starting DNS packet capture on {interface}")
    logger.info(f"Filter: udp port 53")

    def packet_callback(packet):
        logger.info(f"[SNIFFER] Got packet on {interface}")
        if packet.haslayer(IP):
            logger.info(f"[SNIFFER] {packet[IP].src} -> {packet[IP].dst}")
        process_packet(packet)

    try:
        sniff(
            iface=interface,
            filter="udp port 53",
            prn=packet_callback,
            store=0,
        )
    except Exception as e:
        logger.error(f"Sniffer error: {e}")


def process_packet(packet):
    """Procesar paquetes DNS capturados"""
    if not packet.haslayer(DNS):
        return

    logger.info(f"[CAPTURED] DNS packet")

    if packet.haslayer(DNSRR):
        try:
            rdata = packet[DNSRR].rdata
            if isinstance(rdata, bytes):
                rdata = rdata.decode("utf-8")
            if rdata:
                try:
                    ip_address(rdata)
                    if not is_private_ip(rdata):
                        add_to_ipset(rdata)
                except:
                    pass
        except:
            pass


def setup_iptables_redirect(lan_interface, wan_interface):
    """Redirigir DNS queries al proxy local"""
    logger.info("Setting up iptables DNS redirect...")

    run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward", check=False)
    run_cmd("sysctl -w net.ipv4.ip_forward=1", check=False)

    run_cmd("iptables -t nat -F PREROUTING")
    run_cmd("iptables -t nat -F OUTPUT")
    run_cmd("iptables -t filter -F FORWARD")
    run_cmd("iptables -t filter -F INPUT")

    logger.info(f"Redirecting DNS from {lan_interface} to port {LISTEN_PORT}")
    run_cmd(
        f"iptables -t nat -A PREROUTING -i {lan_interface} -p udp --dport 53 -j REDIRECT --to-port {LISTEN_PORT}"
    )

    logger.info("Configuring INPUT rules for DNS proxy...")
    run_cmd(f"iptables -A INPUT -p udp --dport {LISTEN_PORT} -j ACCEPT")

    logger.info("Configuring FORWARD rules...")
    run_cmd("iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    run_cmd("iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP")

    for net in PRIVATE_NETWORKS:
        run_cmd(f"iptables -A FORWARD -d {net} -j ACCEPT")

    run_cmd(f"iptables -A FORWARD -p udp --dport 53 -j ACCEPT")

    for dns in DNS_SERVERS:
        run_cmd(f"iptables -A FORWARD -p udp -d {dns} --dport 53 -j ACCEPT")
        run_cmd(f"iptables -A FORWARD -p udp -s {dns} --sport 53 -j ACCEPT")

    if wan_interface:
        run_cmd(f"iptables -A FORWARD -o {wan_interface} -p udp --dport 53 -j ACCEPT")

    run_cmd(
        f"iptables -A FORWARD -i {lan_interface} -m set ! --match-set {IPSET_NAME} dst -j LOG --log-prefix '[DNS-BLOCKED] '"
    )
    run_cmd(
        f"iptables -A FORWARD -i {lan_interface} -m set ! --match-set {IPSET_NAME} dst -j DROP"
    )

    logger.info("iptables configured with DNS redirect")

    logger.info("Testing DNS redirect rule...")
    test_result = run_cmd(f"iptables -t nat -L PREROUTING -n -v")
    logger.info(f"NAT PREROUTING:\n{test_result.stdout if test_result else 'error'}")

    forward_result = run_cmd(f"iptables -L FORWARD -n -v")
    logger.info(
        f"FORWARD chain:\n{forward_result.stdout if forward_result else 'error'}"
    )


def clear_rules():
    run_cmd("iptables -t nat -F PREROUTING")
    run_cmd("iptables -t nat -F OUTPUT")
    run_cmd("iptables -t filter -F FORWARD")


def parse_args():
    parser = argparse.ArgumentParser(description="DNS Router Controller")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-y", "--yes", action="store_true")
    parser.add_argument("-i", "--interface", required=True, help="LAN interface")
    parser.add_argument("-w", "--wan-interface", help="WAN interface")
    parser.add_argument("--dns", nargs="+", default=DNS_SERVERS)
    parser.add_argument("-b", "--blacklist", help="Blacklist file")
    return parser.parse_args()


def main():
    global DNS_SERVERS, LISTEN_PORT, blacklist_manager

    args = parse_args()
    DNS_SERVERS = args.dns

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        print("Error: Must run as root")
        sys.exit(1)

    blacklist_manager = BlacklistManager()
    if args.blacklist:
        blacklist_manager.load_from_file(args.blacklist)

    print("=" * 60)
    print("DNS Router Controller - Transparent DNS Proxy")
    print("=" * 60)
    print(f"LAN interface: {args.interface}")
    print(f"Proxy port: {LISTEN_PORT}")
    print(f"DNS servers: {args.dns}")
    if args.blacklist:
        print(f"Blacklist: {args.blacklist}")

    if not args.yes:
        print("\nThis will redirect DNS queries and configure iptables.")
        print("Press 'yes' to continue: ", end="")
        if input().strip().lower() != "yes":
            sys.exit(0)

    clear_rules()

    setup_ipset(args.dns)
    setup_iptables_redirect(args.interface, args.wan_interface)

    dns_thread = threading.Thread(target=dns_server_thread, daemon=True)
    dns_thread.start()

    capture_thread = threading.Thread(
        target=capture_dns_packets, args=(args.interface,), daemon=True
    )
    capture_thread.start()

    print("\n" + "=" * 60)
    print("ROUTER CONTROLLER RUNNING")
    print("=" * 60)
    print(f"LAN: {args.interface} -> localhost:{LISTEN_PORT}")
    print(f"DNS: {args.dns}")
    print(f"Block non-allowed IPs: YES")
    print("\nPress Ctrl+C to stop...")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        clear_rules()
        print("Rules cleared.")


if __name__ == "__main__":
    main()
