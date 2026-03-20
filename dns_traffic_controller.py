#!/usr/bin/env python3

import os
import sys
import argparse
import threading
import time
import socket
import subprocess
import logging
from collections import defaultdict
from ipaddress import ip_address, ip_network

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("224.0.0.0/4"),
    ip_network("240.0.0.0/4"),
]

DNS_SERVERS = ["208.67.222.222", "208.67.220.220"]

DOH_BLOCKLIST = {
    # Cloudflare
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    # Google
    "dns.google",
    "dns.google.com",
    # Quad9
    "dns.quad9.net",
    "dns9.quad9.net",
    # AdGuard
    "dns.adguard-dns.com",
    "dns-unfiltered.adguard-dns.com",
    "family.adguard-dns.com",
    # NextDNS
    "dns.nextdns.io",
    "dns.nextdns.com",
    # Others
    "doh.li",
    "doh.slashdotted.org",
    "doh.dnshome.de",
    "dns.twnic.tw",
    "rdns.faelix.net",
    "doh.ffmuc.net",
    "doh.cry.to",
    "doh.dnsprivacy.at",
    "doh.fdn.fr",
    "doh.knot-resolver.cz",
    "odoh.cloudflare.com",
    "doh2.doh.sb",
    "dns.0xen.io",
    "dns.overpriv.io",
    "doh.tiarap.org",
    "doh.ffmuc.net",
    "doh.li",
    "doh.xOBSCENE.com",
    "dns.rubyfish.cn",
    "doh.xOBSCENE.com",
    # Apple
    "mask.icloud-dns.com",
    "mask-h2.icloud-dns.com",
}

DOH_IPS = {
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "185.235.81.1",
    "185.235.81.2",
    "45.90.28.0",
    "45.90.30.0",
}

DOT_DOMAINS = {
    "dns.google",
    "cloudflare-dns.com",
    "dns.quad9.net",
    "dns.nextdns.io",
    "dns.adguard-dns.com",
    "dns.dot.radius-one.com",
    "doh.li",
}

PROXY_PORTS = {
    "http": [3128, 8080, 8888, 8000, 8008, 8081, 8123],
    "socks4": [1080, 9050, 9051],
    "socks5": [1080, 9050, 9051, 51820],
    "ssl-proxy": [8443, 9443, 10443],
}

TUNNEL_DOMAINS = {
    # Cloudflare Tunnel
    "cloudflaretunnel.com",
    "*.cloudflaretunnel.com",
    "trycloudflare.com",
    # ngrok
    "ngrok.io",
    "ngrok.com",
    "*.ngrok.io",
    # localtunnel
    "localtunnel.me",
    "lt.io",
    # serveo
    "serveo.net",
    # telebit
    "telebit.io",
    "telebit.cloud",
    # hoppy
    "hoppy.network",
    # cloudfront tunnels
    "tunnel.pyjam.as",
    # misc
    "tunnelto.dev",
    "frp.io",
    "localhost.run",
    " Serveo",
}

TUNNEL_IPS = {
    # Cloudflare
    "104.16.0.0/12",
    # ngrok
    "3.0.0.0/8",
    # Known tunnel IPs (dynamic)
}

QUIC_PORTS = [443, 80]
VPN_PORTS = {
    "openvpn": [1194, 1195, 1196, 1197, 443, 1198, 1723],
    "wireguard": [51820, 51821, 51822, 51823, 51824, 51825],
    "tor": [9001, 9030, 9050, 9051, 9053, 9150, 9151, 4242, 5353],
    "pptp": [1723],
    "ipsec": [500, 4500, 1701],
    "ikev2": [500, 4500],
    "vpn_common": [1194, 443, 1723, 51820, 9201, 943, 445, 8080, 3128],
    "wireguard": [51820, 51821, 51822],
    "zerotier": [9993, 3443],
    "tailscale": [41641],
}

EVASION_PORTS = {
    "dns-alt": [5353, 5355, 5533, 8530],
    "obfuscated": [8443, 8531, 8835, 9753],
    "custom-dns": [10053, 11053, 15053, 25053],
}

MISC_BLOCKED_PORTS = {
    "remote-desktop": [3389, 5900, 5901, 5902],
    "file-transfer": [20, 21, 69, 115, 139, 445],
    "p2p": [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6890],
    "mail": [25, 110, 143, 465, 587, 993, 995],
}

VERBOSE = False
logger = None


LOG_DIR = "/var/log/dns-controller"
LOG_FILE = os.path.join(LOG_DIR, "dns-controller.log")
CONFIG_DIR = "/etc/dns-controller"


def setup_logging(verbose=False, log_to_file=True):
    global logger
    level = logging.DEBUG if verbose else logging.INFO

    handlers = []

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    handlers.append(console_handler)

    if log_to_file:
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            file_handler = logging.FileHandler(LOG_FILE)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            handlers.append(file_handler)
        except PermissionError:
            pass

    logging.basicConfig(level=level, handlers=handlers)
    logger = logging.getLogger(__name__)


class BlacklistManager:
    def __init__(self):
        self.blacklisted_domains = set()
        self.blacklisted_ips = set()
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

    def block_ip(self, ip_str):
        with self.lock:
            self.blacklisted_ips.add(ip_str)
        logger.info(f"[BLACKLIST IP] {ip_str}")

    def unblock_ip(self, ip_str):
        with self.lock:
            self.blacklisted_ips.discard(ip_str)
        logger.info(f"[UNBLOCKED] {ip_str}")


class DNSTrafficController:
    def __init__(
        self, dns_servers=None, interface=None, resolve_cooldown=30, blacklist=None
    ):
        self.dns_servers = dns_servers or DNS_SERVERS
        self.interface = interface
        self.allowed_ips = set()
        self.blocked_ips = set()
        self.dns_cache = {}
        self.resolution_attempts = {}
        self.resolve_cooldown = resolve_cooldown
        self.blacklist = blacklist or BlacklistManager()
        self.lock = threading.Lock()
        self.running = False

        self._add_dns_servers_to_allowed()

    def _add_dns_servers_to_allowed(self):
        for dns in self.dns_servers:
            self.allowed_ips.add(dns)
        logger.info(f"Added DNS servers to allowed list: {self.dns_servers}")

    def is_private_ip(self, ip_str):
        try:
            ip = ip_address(ip_str)
            for network in PRIVATE_NETWORKS:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    def is_ip_allowed(self, ip_str):
        with self.lock:
            return ip_str in self.allowed_ips or self.is_private_ip(ip_str)

    def add_allowed_ip(self, ip_str):
        with self.lock:
            if ip_str not in self.allowed_ips and not self.is_private_ip(ip_str):
                self.allowed_ips.add(ip_str)
                if ip_str in self.blocked_ips:
                    self.blocked_ips.discard(ip_str)
                self._allow_ip_iptables(ip_str)
                logger.info(f"[ALLOWED] {ip_str}")

    def _allow_ip_iptables(self, ip_str):
        try:
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "-d", ip_str, "-j", "ACCEPT"],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Could not add iptables rule for {ip_str}: {e}")

    def get_domain_from_cache(self, ip_str):
        with self.lock:
            for domain, resolved_ip in self.dns_cache.items():
                if resolved_ip == ip_str:
                    return domain
        return None

    def is_valid_domain(self, hostname):
        if hostname.endswith(".in-addr.arpa"):
            return False
        if hostname.replace(".", "").isdigit():
            return False
        return True

    def can_resolve(self, hostname):
        if hostname in self.dns_cache:
            return False
        now = time.time()
        with self.lock:
            if hostname in self.resolution_attempts:
                last_attempt = self.resolution_attempts[hostname]
                if now - last_attempt < self.resolve_cooldown:
                    return False
            self.resolution_attempts[hostname] = now
        return True

    def resolve_and_allow(self, hostname):
        if not self.is_valid_domain(hostname):
            logger.debug(f"[SKIP] Invalid domain type: {hostname}")
            return None

        if self.blacklist.is_blacklisted(hostname):
            logger.info(f"[BLACKLISTED] {hostname} - blocked by blacklist")
            return "BLOCKED"

        if not self.can_resolve(hostname):
            logger.debug(f"[SKIP] Cooldown active: {hostname}")
            return None

        try:
            ip_str = socket.gethostbyname(hostname)
            with self.lock:
                self.dns_cache[hostname] = ip_str

            if self.blacklist.is_blacklisted(ip_str):
                logger.info(f"[BLACKLISTED] {hostname} -> {ip_str} - IP in blacklist")
                return "BLOCKED"

            self.add_allowed_ip(ip_str)
            logger.info(f"[RESOLVED] {hostname} -> {ip_str}")
            return ip_str
        except socket.gaierror as e:
            logger.debug(f"[RESOLVE FAILED] {hostname}: {e}")
            return None

    def save_ips(self, filepath=None):
        if filepath is None:
            filepath = os.path.join(CONFIG_DIR, "allowed_ips.txt")

        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with self.lock:
                ips_to_save = self.allowed_ips - set(self.dns_servers)

            with open(filepath, "w") as f:
                f.write(
                    f"# Allowed IPs saved at {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                for ip in sorted(ips_to_save):
                    f.write(f"{ip}\n")

            with self.lock:
                domains_to_save = dict(self.dns_cache)

            with open(filepath + ".domains", "w") as f:
                f.write(f"# DNS cache saved at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                for domain, ip in sorted(domains_to_save.items()):
                    f.write(f"{ip} {domain}\n")

            logger.info(f"Saved {len(ips_to_save)} IPs to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save IPs: {e}")
            return False

    def load_ips(self, filepath=None):
        if filepath is None:
            filepath = os.path.join(CONFIG_DIR, "allowed_ips.txt")

        if not os.path.exists(filepath):
            logger.info(f"No saved IPs file found at {filepath}")
            return 0

        loaded_count = 0
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                ip = line.split()[0]
                try:
                    ip_address(ip)
                    self.add_allowed_ip(ip)
                    loaded_count += 1
                except ValueError:
                    continue

        if os.path.exists(filepath + ".domains"):
            with open(filepath + ".domains", "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        with self.lock:
                            self.dns_cache[parts[1]] = parts[0]

        logger.info(f"Loaded {loaded_count} IPs from {filepath}")
        return loaded_count


def clear_dns_cache():
    logger.info("Clearing DNS cache...")

    commands = [
        ["systemd-resolve", "--flush-caches"],
        ["resolvectl", "flush-caches"],
        ["service", "nscd", "restart"],
        ["systemctl", "restart", "systemd-resolved"],
    ]

    for cmd in commands:
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"DNS cache cleared successfully using: {' '.join(cmd)}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    pass
        subprocess.run(
            ["sh", "-c", 'echo "" > /etc/ppp/resolv.conf'], capture_output=True
        )
    except Exception:
        pass

    logger.warning("Could not clear DNS cache - trying alternative methods")
    return False


def flush_iptables_rules(preserve_nat=False):
    logger.warning("Flushing iptables rules...")

    if preserve_nat:
        logger.info("Preserving NAT table (for router mode)")
        tables = ["filter", "mangle", "raw", "security"]
    else:
        tables = ["filter", "nat", "mangle", "raw", "security"]

    for table in tables:
        try:
            subprocess.run(
                ["iptables", "-t", table, "-F"], check=True, capture_output=True
            )
            subprocess.run(
                ["iptables", "-t", table, "-X"], check=True, capture_output=True
            )
        except subprocess.CalledProcessError:
            pass

    if not preserve_nat:
        try:
            subprocess.run(
                ["iptables", "-P", "INPUT", "ACCEPT"], check=True, capture_output=True
            )
            subprocess.run(
                ["iptables", "-P", "FORWARD", "ACCEPT"], check=True, capture_output=True
            )
            subprocess.run(
                ["iptables", "-P", "OUTPUT", "DROP"], check=True, capture_output=True
            )
        except subprocess.CalledProcessError:
            logger.error("Could not set default policies")
            return False
    else:
        try:
            subprocess.run(
                ["iptables", "-P", "INPUT", "ACCEPT"], check=True, capture_output=True
            )
            subprocess.run(
                ["iptables", "-P", "FORWARD", "ACCEPT"], check=True, capture_output=True
            )
            subprocess.run(
                ["iptables", "-P", "OUTPUT", "DROP"], check=True, capture_output=True
            )
            subprocess.run(
                ["iptables", "-t", "nat", "-P", "PREROUTING", "ACCEPT"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["iptables", "-t", "nat", "-P", "POSTROUTING", "ACCEPT"],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            pass

    logger.info("Iptables rules flushed")
    return True


def setup_iptables_base(controller, block_quic=True, block_vpn=True, block_doh=True):
    logger.info("Setting up base iptables rules...")

    try:
        subprocess.run(
            [
                "iptables",
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        pass

    try:
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "ACCEPT"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        pass

    try:
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        pass

    for dns_ip in controller.dns_servers:
        try:
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", dns_ip, "-j", "ACCEPT"],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            pass

    for network in PRIVATE_NETWORKS:
        try:
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", str(network), "-j", "ACCEPT"],
                check=True,
                capture_output=True,
            )
            logger.info(f"Allowed private network: {network}")
        except subprocess.CalledProcessError:
            pass

    if block_quic:
        logger.info("Blocking QUIC/HTTP3 (UDP 443)...")
        try:
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "OUTPUT",
                    "-p",
                    "udp",
                    "--dport",
                    "443",
                    "-j",
                    "DROP",
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            pass

    if block_doh:
        logger.info("Blocking DoH domains and IPs...")
        for doh_domain in DOH_BLOCKLIST:
            controller.blacklist.blacklisted_domains.add(doh_domain)
            logger.debug(f"Added DoH domain to blacklist: {doh_domain}")

        for doh_ip in DOH_IPS:
            if doh_ip not in controller.dns_servers:
                try:
                    subprocess.run(
                        ["iptables", "-A", "OUTPUT", "-d", doh_ip, "-j", "DROP"],
                        check=True,
                        capture_output=True,
                    )
                    logger.info(f"[BLOCKED DoH IP] {doh_ip}")
                except subprocess.CalledProcessError:
                    pass

    if block_vpn:
        logger.info("Blocking VPN ports...")
        blocked_ports = set()
        for vpn_type, ports in VPN_PORTS.items():
            for port in ports:
                if port not in blocked_ports:
                    blocked_ports.add(port)
                    try:
                        subprocess.run(
                            [
                                "iptables",
                                "-A",
                                "OUTPUT",
                                "-p",
                                "tcp",
                                "--dport",
                                str(port),
                                "-j",
                                "DROP",
                            ],
                            check=True,
                            capture_output=True,
                        )
                        subprocess.run(
                            [
                                "iptables",
                                "-A",
                                "OUTPUT",
                                "-p",
                                "udp",
                                "--dport",
                                str(port),
                                "-j",
                                "DROP",
                            ],
                            check=True,
                            capture_output=True,
                        )
                    except subprocess.CalledProcessError:
                        pass
        logger.info(f"Blocked {len(blocked_ports)} VPN ports")

    logger.info("Blocking DNS over TLS (DoT) port 853...")
    try:
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "853", "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "853", "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        logger.info("Blocked DoT (port 853)")
    except:
        pass

    logger.info("Blocking proxy ports...")
    proxy_ports_blocked = set()
    for proxy_type, ports in PROXY_PORTS.items():
        for port in ports:
            if port not in proxy_ports_blocked:
                proxy_ports_blocked.add(port)
                try:
                    subprocess.run(
                        [
                            "iptables",
                            "-A",
                            "OUTPUT",
                            "-p",
                            "tcp",
                            "--dport",
                            str(port),
                            "-j",
                            "DROP",
                        ],
                        check=True,
                        capture_output=True,
                    )
                except:
                    pass
    logger.info(f"Blocked {len(proxy_ports_blocked)} proxy ports")

    logger.info("Blocking alternate DNS and evasion ports...")
    evasion_ports_blocked = set()
    for category, ports in EVASION_PORTS.items():
        for port in ports:
            if port not in evasion_ports_blocked:
                evasion_ports_blocked.add(port)
                try:
                    subprocess.run(
                        [
                            "iptables",
                            "-A",
                            "OUTPUT",
                            "-p",
                            "tcp",
                            "--dport",
                            str(port),
                            "-j",
                            "DROP",
                        ],
                        check=True,
                        capture_output=True,
                    )
                    subprocess.run(
                        [
                            "iptables",
                            "-A",
                            "OUTPUT",
                            "-p",
                            "udp",
                            "--dport",
                            str(port),
                            "-j",
                            "DROP",
                        ],
                        check=True,
                        capture_output=True,
                    )
                except:
                    pass
    logger.info(f"Blocked {len(evasion_ports_blocked)} evasion ports")

    if block_doh:
        logger.info("Blocking tunneling domains...")
        for tunnel_domain in TUNNEL_DOMAINS:
            controller.blacklist.blacklisted_domains.add(tunnel_domain)
            logger.debug(f"Added tunnel domain to blacklist: {tunnel_domain}")

    logger.info("Base iptables rules configured")


packet_queue = []
queue_lock = threading.Lock()
last_log_time = {}
LOG_THROTTLE = 5


def should_log(key):
    """Rate limiting for logs"""
    now = time.time()
    with queue_lock:
        if key in last_log_time:
            if now - last_log_time[key] < LOG_THROTTLE:
                return False
        last_log_time[key] = now
        return True


def process_packet(controller, packet):
    if not packet.haslayer(IP):
        return

    try:
        dst_ip = packet[IP].dst
    except:
        return

    if controller.is_ip_allowed(dst_ip):
        return

    with controller.lock:
        is_new_blocked = dst_ip not in controller.blocked_ips
        controller.blocked_ips.add(dst_ip)

    if is_new_blocked and should_log("blocked"):
        logger.info(f"[BLOCKED] {dst_ip}")

    if packet.haslayer(DNSQR):
        try:
            dns_qry = packet[DNSQR]
            query_name = dns_qry.qname.decode("utf-8").rstrip(".")
            if should_log(f"query_{query_name}"):
                logger.debug(f"[DNS QUERY] {query_name}")

            resolved_ip = controller.resolve_and_allow(query_name)
            if resolved_ip and should_log(f"resolved_{query_name}"):
                logger.info(f"[RESOLVED] {query_name} -> {resolved_ip}")
        except:
            pass

    if packet.haslayer(DNSRR):
        try:
            dns_resp = packet[DNSRR]
            if dns_resp.rdata:
                resolved_ip = (
                    dns_resp.rdata.decode("utf-8")
                    if isinstance(dns_resp.rdata, bytes)
                    else str(dns_resp.rdata)
                )
                controller.add_allowed_ip(resolved_ip)
                if should_log(f"cache_{resolved_ip}"):
                    logger.debug(f"[DNS CACHE] {resolved_ip}")
        except:
            pass


def verify_and_setup_nat(wan_interface=None):
    """Verify NAT is configured, set it up if missing"""
    logger.info("Verifying NAT configuration...")

    if wan_interface is None:
        wan_interface = get_default_gateway_interface()

    if wan_interface is None:
        logger.error("Cannot detect WAN interface for NAT")
        return False

    result = subprocess.run(
        ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n"],
        capture_output=True,
        text=True,
    )

    has_masquerade = wan_interface in result.stdout or "+" in result.stdout

    if has_masquerade:
        logger.info(f"NAT already configured for {wan_interface}")
        return True

    logger.info(f"Configuring NAT (MASQUERADE) on {wan_interface}...")

    subprocess.run(
        [
            "iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            wan_interface,
            "-j",
            "MASQUERADE",
        ],
        capture_output=True,
    )

    subprocess.run(
        [
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            "eth1",
            "-o",
            wan_interface,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
    )

    subprocess.run(
        [
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            "eth1",
            "-o",
            wan_interface,
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
    )

    logger.info("NAT configured successfully")
    return True


def packet_sniffer(controller, interface=None, router_mode=False):
    logger.info(
        f"Starting packet sniffer on interface: {interface or 'all'} (router_mode={router_mode})"
    )

    if router_mode:
        logger.info("Router mode: capturing FORWARD traffic only")
        try:
            sniff(
                filter="forward",
                prn=lambda p: process_packet(controller, p),
                store=0,
                iface=interface,
                stop_filter=lambda p: not controller.running,
            )
        except Exception as e:
            logger.debug(f"Forward filter not supported, using all: {e}")
            try:
                sniff(
                    filter="ip",
                    prn=lambda p: process_packet(controller, p),
                    store=0,
                    iface=interface,
                    stop_filter=lambda p: not controller.running,
                )
            except Exception as e2:
                logger.error(f"Sniffer failed: {e2}")
    else:
        try:
            sniff(
                filter="outbound",
                prn=lambda p: process_packet(controller, p),
                store=0,
                iface=interface,
                stop_filter=lambda p: not controller.running,
            )
        except Exception as e:
            logger.debug(f"Outbound filter not supported: {e}")
            try:
                sniff(
                    filter="tcp or udp",
                    prn=lambda p: process_packet(controller, p),
                    store=0,
                    iface=interface,
                    stop_filter=lambda p: not controller.running,
                )
            except Exception as e2:
                logger.error(f"Alternative sniffer also failed: {e2}")


def get_user_confirmation():
    print("\n" + "=" * 60)
    print("WARNING: This will FLUSH ALL iptables rules and set")
    print("default OUTPUT policy to DROP")
    print("=" * 60)
    print("\nThis will block ALL outbound network traffic except:")
    print("  - DNS (port 53)")
    print("  - Private local networks")
    print("  - IPs resolved via DNS queries")
    print("\nPress 'yes' to continue or 'no' to cancel: ", end="")

    response = input().strip().lower()
    return response == "yes"


def parse_args():
    parser = argparse.ArgumentParser(
        description="DNS Traffic Controller - Restrict outbound network traffic"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all allowed/blocked IPs in console",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="Skip confirmation prompt"
    )
    parser.add_argument(
        "--dns",
        nargs="+",
        default=DNS_SERVERS,
        help="DNS servers to use (default: OpenDNS)",
    )
    parser.add_argument(
        "-b",
        "--blacklist",
        nargs="+",
        default=[],
        help="Blacklist files (one domain per line, use * for wildcards, ! for whitelist)",
    )
    parser.add_argument(
        "--blocklist",
        nargs="+",
        default=[],
        help="Alias for --blacklist",
    )
    parser.add_argument(
        "--no-quic",
        action="store_true",
        help="Don't block QUIC/HTTP3 (UDP 443)",
    )
    parser.add_argument(
        "--no-vpn",
        action="store_true",
        help="Don't block VPN ports",
    )
    parser.add_argument(
        "--no-doh",
        action="store_true",
        help="Don't block DoH domains and IPs",
    )
    parser.add_argument(
        "--force-dns",
        action="store_true",
        help="Force local DNS by modifying /etc/resolv.conf",
    )
    parser.add_argument(
        "--router",
        action="store_true",
        help="Enable router mode (forward traffic, act as gateway)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        dest="capture_interface",
        metavar="IFACE",
        help="Network interface to capture traffic on (in router mode, typically the LAN interface)",
    )
    parser.add_argument(
        "--load-ips",
        metavar="FILE",
        nargs="?",
        const="default",
        help="Load previously saved IPs (default: /etc/dns-controller/allowed_ips.txt)",
    )
    parser.add_argument(
        "--save-ips",
        metavar="FILE",
        nargs="?",
        const="default",
        help="Save learned IPs to file on exit (default: /etc/dns-controller/allowed_ips.txt)",
    )
    parser.add_argument(
        "--no-log-file",
        action="store_true",
        help="Disable logging to file",
    )
    return parser.parse_args()


def force_local_dns(dns_servers):
    """Force system to use local DNS servers"""
    logger.info("Forcing local DNS configuration...")

    resolv_conf = "/etc/resolv.conf"
    resolv_conf_head = "/etc/resolv.conf.head"

    try:
        with open(resolv_conf_head, "w") as f:
            f.write("# DNS Controller - Forced DNS\n")
            for dns in dns_servers:
                f.write(f"nameserver {dns}\n")

        with open(resolv_conf, "r") as f:
            content = f.read()

        modified = False
        new_lines = []
        for line in content.split("\n"):
            if line.strip().startswith("nameserver"):
                if not modified:
                    new_lines.append(f"nameserver {dns_servers[0]}")
                    modified = True
            else:
                new_lines.append(line)

        if not modified:
            new_lines.insert(0, f"nameserver {dns_servers[0]}")

        with open(resolv_conf, "w") as f:
            f.write("\n".join(new_lines))

        logger.info(f"Local DNS forced to: {dns_servers}")

    except PermissionError:
        logger.warning("Cannot modify /etc/resolv.conf - need root or chattr")
    except Exception as e:
        logger.warning(f"Could not force local DNS: {e}")

    try:
        subprocess.run(["systemd-resolve", "--flush-caches"], capture_output=True)
        subprocess.run(["resolvectl", "flush-caches"], capture_output=True)
    except:
        pass


def get_default_gateway_interface():
    """Detect the default gateway interface (WAN)"""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if parts and parts[0] == "default":
                    for i, part in enumerate(parts):
                        if part == "dev" and i + 1 < len(parts):
                            return parts[i + 1]
    except:
        pass
    return None


def setup_router_mode():
    """Enable IP forwarding and routing"""
    logger.info("Enabling router mode...")

    wan_interface = get_default_gateway_interface()
    if wan_interface:
        logger.info(f"Detected WAN interface: {wan_interface}")
    else:
        logger.warning("Could not detect WAN interface, using 'auto'")
        wan_interface = "+"

    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

    try:
        with open("/etc/sysctl.conf", "r") as f:
            content = f.read()
        if "net.ipv4.ip_forward=1" not in content:
            with open("/etc/sysctl.conf", "a") as f:
                f.write("\nnet.ipv4.ip_forward=1\n")
    except:
        pass

    logger.info("Setting up FORWARD rules...")
    subprocess.run(
        [
            "iptables",
            "-A",
            "FORWARD",
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
    )
    subprocess.run(
        ["iptables", "-A", "FORWARD", "-i", "lo", "-j", "ACCEPT"], capture_output=True
    )
    subprocess.run(["iptables", "-A", "FORWARD", "-j", "LOG"], capture_output=True)

    logger.info("Setting up NAT (masquerade)...")
    subprocess.run(
        [
            "iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            wan_interface,
            "-j",
            "MASQUERADE",
        ],
        capture_output=True,
    )

    logger.info("Router mode enabled successfully")


def main():
    global DNS_SERVERS

    args = parse_args()
    setup_logging(verbose=args.verbose, log_to_file=not args.no_log_file)

    DNS_SERVERS = args.dns

    blacklist_files = args.blacklist or args.blocklist or []

    print("=" * 60)
    print("DNS Traffic Controller - Network Output Restrictor")
    print("=" * 60)

    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        sys.exit(1)

    if not args.yes and not get_user_confirmation():
        print("Cancelled by user")
        sys.exit(0)

    logger.info("Starting DNS Traffic Controller...")

    if args.force_dns:
        force_local_dns(DNS_SERVERS)

    blacklist_manager = BlacklistManager()
    for bl_file in blacklist_files:
        blacklist_manager.load_from_file(bl_file)

    clear_dns_cache()

    flush_iptables_rules(preserve_nat=args.router)

    if args.router:
        logger.info("Configuring router mode...")
        capture_iface = args.capture_interface or "eth1"
        logger.info(f"Capturing on interface: {capture_iface}")
        setup_router_mode()
        verify_and_setup_nat()

    controller = DNSTrafficController(
        dns_servers=DNS_SERVERS, blacklist=blacklist_manager
    )

    if args.load_ips:
        load_file = args.load_ips if args.load_ips != "default" else None
        loaded = controller.load_ips(load_file)
        if loaded > 0:
            logger.info(f"Loaded {loaded} IPs from previous session")
        elif loaded == 0:
            logger.info("No saved IPs found, will learn new ones")

    setup_iptables_base(
        controller,
        block_quic=not args.no_quic,
        block_vpn=not args.no_vpn,
        block_doh=not args.no_doh,
    )

    controller.running = True

    capture_iface = args.capture_interface if args.router else None
    sniffer_thread = threading.Thread(
        target=packet_sniffer,
        args=(controller, capture_iface, args.router),
        daemon=True,
    )
    sniffer_thread.start()

    print("\n" + "=" * 60)
    print("CONTROLLER RUNNING")
    print("=" * 60)
    print(f"\nDNS servers: {', '.join(DNS_SERVERS)}")
    print("Allowed private networks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
    print(f"Verbose mode: {'ON' if args.verbose else 'OFF'}")
    print(f"Router mode: {'ON' if args.router else 'OFF'}")
    if args.router:
        print(f"Capture interface: {capture_iface or 'auto'}")
    print("\nPress Ctrl+C to stop...")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        controller.running = False

    if args.save_ips:
        save_file = args.save_ips if args.save_ips != "default" else None
        controller.save_ips(save_file)

    print("\n" + "=" * 60)
    print("SESSION STATS")
    print("=" * 60)
    print(f"Allowed IPs: {len(controller.allowed_ips)}")
    print(f"Blocked IPs: {len(controller.blocked_ips)}")
    print(f"DNS Cache entries: {len(controller.dns_cache)}")
    print("\nNote: Iptables rules are still in place.")
    print("To reset: iptables -P OUTPUT ACCEPT")
    print(f"Logs saved to: {LOG_FILE}")


if __name__ == "__main__":
    main()
