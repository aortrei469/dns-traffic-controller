#!/usr/bin/env python3
"""
DNS Controller Router Setup
Configura el sistema como gateway DNS para la red local
"""

import os
import sys
import subprocess
import argparse

def run(cmd, check=True):
    """Ejecutar comando shell"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    return True

def install_dependencies():
    """Instalar dependencias necesarias"""
    print("Instalando dependencias...")
    run("apt update")
    run("apt install -y dnsmasq iptables python3-pip")
    run("pip3 install scapy")

def configure_dnsmasq(dns_servers):
    """Configurar dnsmasq para reenviar DNS"""
    print("Configurando dnsmasq...")
    
    config = f"""
# DNS Controller - dnsmasq configuration
# No usar /etc/resolv.conf
no-resolv

# Servidores DNS upstream
"""
    for dns in dns_servers:
        config += f"server={dns}\n"
    
    config += """
# Cache DNS
cache-size=1000

# Log
log-queries
log-facility=/var/log/dnsmasq.log

# Escuchar solo en interfaz local
interface=lo
bind-interfaces
"""
    
    with open('/etc/dnsmasq.d/dns-controller.conf', 'w') as f:
        f.write(config)
    
    run("systemctl restart dnsmasq")
    print("dnsmasq configurado")

def setup_iptables_redirect():
    """Redirigir tráfico DNS al servidor local"""
    print("Configurando redirección DNS...")
    
    #允许 DNS
    run("iptables -A INPUT -p udp --dport 53 -j ACCEPT")
    run("iptables -A INPUT -p tcp --dport 53 -j ACCEPT")
    
    # Redirigir consultas DNS salientes
    run("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53")
    run("iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 53")
    
    print("Redirección configurada")

def configure_dhcp_server(dns_server_ip):
    """Configurar DHCP para asignar este DNS (opcional)"""
    print(f"\nPara configurar DHCP, añade en tu router:")
    print(f"  DNS Primario: {dns_server_ip}")
    print(f"  DNS Secundario: 208.67.222.222")
    print("\nO si usas isc-dhcp-server:")
    
    dhcp_conf = f"""
option domain-name-servers {dns_server_ip}, 208.67.222.222;
"""
    print(dhcp_conf)

def enable_ip_forward():
    """Habilitar forwarding IP"""
    with open('/etc/sysctl.conf', 'r') as f:
        content = f.read()
    
    if 'net.ipv4.ip_forward=1' not in content:
        with open('/etc/sysctl.conf', 'a') as f:
            f.write('\nnet.ipv4.ip_forward=1\n')
    
    run("sysctl -p net.ipv4.ip_forward=1")
    print("IP forwarding habilitado")

def main():
    parser = argparse.ArgumentParser(description="DNS Controller Router Setup")
    parser.add_argument('--dns', nargs='+', default=['208.67.222.222', '208.67.220.220'],
                       help='DNS servers upstream')
    parser.add_argument('--install', action='store_true', help='Instalar dependencias')
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("Ejecutar como root")
        sys.exit(1)
    
    print("=" * 60)
    print("DNS Controller - Router Setup")
    print("=" * 60)
    
    if args.install:
        install_dependencies()
    
    configure_dnsmasq(args.dns)
    setup_iptables_redirect()
    enable_ip_forward()
    
    # Obtener IP local
    result = subprocess.run("hostname -I | awk '{print $1}'", 
                          shell=True, capture_output=True, text=True)
    local_ip = result.stdout.strip()
    
    configure_dhcp_server(local_ip)
    
    print("\n" + "=" * 60)
    print("CONFIGURACIÓN COMPLETA")
    print("=" * 60)
    print(f"\nIP del servidor DNS: {local_ip}")
    print("\nPara completar:")
    print("1. Configura tu router DHCP para usar esta IP como DNS")
    print("2. O ejecuta: sudo systemctl restart network-manager")
    print("\nVerificar estado:")
    print("  sudo systemctl status dnsmasq")
    print("  sudo iptables -t nat -L -n")

if __name__ == '__main__':
    main()
