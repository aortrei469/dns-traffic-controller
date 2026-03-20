# DNS Traffic Controller

**Control parental y de red avanzado con protección contra evasión**

Sistema de filtrado de tráfico de red que restrict el acceso a internet:
- Direcciones IP privadas locales
- IPs resueltas vía DNS controlado
- Listas negras personalizables
- Bloqueo completo de DoH, DoT, QUIC, VPNs, proxies y túneles

---

## Tabla de Contenidos

1. [Instalación](#instalación)
2. [Modo PC Individual](#modo-pc-individual)
3. [Modo Router](#modo-router)
4. [Opciones de Línea de Comandos](#opciones-de-línea-de-comandos)
5. [Bloqueos Automáticos](#bloqueos-automáticos)
6. [Listas Negras](#listas-negras)
7. [Logs y Persistencia](#logs-y-persistencia)
8. [Comandos de Emergencia](#comandos-de-emergencia)
9. [Solución de Problemas](#solución-de-problemas)

---

## Instalación

### Opción A: Instalador interactivo (recomendado)

```bash
cd /home/admon/opencodeDNS
sudo ./install.sh
```

### Opción B: Instalación manual

```bash
sudo apt update
sudo apt install python3-pip iptables
sudo pip3 install scapy

sudo cp dns_traffic_controller.py /usr/local/bin/
sudo chmod +x /usr/local/bin/dns_traffic_controller.py
```

---

## Modo PC Individual

Para controlar un solo equipo (ej: ordenador de un niño).

```
[PC Niño] → [DNS Controller] → [Router] → [Internet]
```

### Comandos de uso

```bash
# 1. Prueba básica (sin blacklist)
sudo python3 dns_traffic_controller.py -v -y

# 2. Modo Parental
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt

# 3. Con forzar DNS local
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --force-dns

# 4. Guardar IPs aprendidas (al salir)
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --save-ips

# 5. Cargar IPs guardadas (al iniciar)
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --load-ips

# 6. Sesión completa (cargar + guardar)
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --load-ips --save-ips
```

---

## Modo Router

Para controlar toda una red de aula o laboratorio.

```
[ISP] → [Mikrotik] → [PC Router Ubuntu] → [Red de alumnos]
```

### Características del modo router

- **NAT automático**: Verifica y configura MASQUERADE si falta
- **Captura FORWARD**: Solo tráfico de clientes, no del router
- **Rate limiting**: Logs optimizados para alto tráfico
- **Persistencia**: Carga IPs conocidas, guarda aprendidas

### 1. Configurar interfaces de red

Edita `/etc/netplan/01-netcfg.yaml`:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:  # WAN (hacia Mikrotik/ISP)
      dhcp4: yes
    eth1:  # LAN (hacia red de alumnos)
      addresses:
        - 192.168.100.1/24
      dhcp4: no
```

Aplicar:
```bash
sudo netplan apply
```

### 2. Habilitar IP Forwarding

```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 3. Limpiar reglas existentes

```bash
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

### 4. Ejecutar

#### Ver interfaces disponibles
```bash
ip link show
# o
ip addr
```

#### Especificar interfaz de captura

Cuando el router tiene múltiples interfaces, especifica la LAN (donde están los clientes):

```bash
cd /home/admon/opencodeDNS
sudo python3 dns_traffic_controller.py -v -y \
    --router \
    -i eth1 \
    --blacklist blacklists/educational.txt \
    --load-ips \
    --save-ips
```

| Opción | Descripción |
|--------|-------------|
| `-i eth1` | Interfaz LAN donde están los clientes (default: eth1) |

#### Auto-detección
```bash
# Sin especificar (usa eth1 por defecto)
sudo python3 dns_traffic_controller.py -v -y \
    --router \
    --blacklist blacklists/educational.txt \
    --load-ips --save-ips
```

### 5. Verificar funcionamiento

```bash
# Ver NAT configurado
sudo iptables -t nat -L POSTROUTING -n -v

# Ver reglas FORWARD
sudo iptables -L FORWARD -n -v

# Ver logs en tiempo real
sudo tail -f /var/log/dns-controller/dns-controller.log
```

### 6. (Opcional) Configurar DHCP con dnsmasq

```bash
sudo apt install dnsmasq

sudo nano /etc/dnsmasq.d/dns-controller.conf
```

Contenido:
```conf
interface=eth1
dhcp-range=192.168.100.10,192.168.100.250,24h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
server=208.67.222.222
server=208.67.220.220
```

```bash
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq
```

---

## Opciones de Línea de Comandos

| Opción | Descripción |
|--------|-------------|
| `-v, --verbose` | Mostrar logs detallados en consola |
| `-y, --yes` | Saltar confirmación |
| `--dns IP [IP...]` | Servidores DNS (default: OpenDNS) |
| `-b, --blacklist FILE` | Archivos de lista negra |
| `--no-quic` | No bloquear QUIC/HTTP3 |
| `--no-vpn` | No bloquear puertos VPN |
| `--no-doh` | No bloquear DoH |
| `--force-dns` | Forzar DNS local |
| `--router` | Modo router/gateway |
| `-i, --interface IFACE` | Interfaz de captura (LAN, default: eth1) |
| `--load-ips [FILE]` | Cargar IPs guardadas |
| `--save-ips [FILE]` | Guardar IPs al salir |
| `--no-log-file` | No guardar logs a archivo |

---

## Bloqueos Automáticos

### DoH/DoT (35+ dominios)
```
cloudflare-dns.com, dns.google, dns.quad9.net, 
dns.nextdns.io, dns.adguard-dns.com, etc.
```

### DNS sobre TLS
```
Puerto 853 (TCP/UDP)
```

### QUIC/HTTP3
```
Puerto 443 (UDP)
```

### VPNs
```
OpenVPN: 1194, 443
WireGuard: 51820
Tor: 9001, 9050, 9051
IPSec: 500, 4500
```

### Proxies
```
HTTP: 3128, 8080, 8888
SOCKS: 1080, 9050
```

### Túneles
```
ngrok, Cloudflare Tunnel, localtunnel, serveo, telebit
```

---

## Listas Negras

### Formato
```
# Comentarios
dominio.com              # Bloquea dominio y subdominios
*.dominio.com           # Bloquea solo subdominios
!dominio.com            # Whitelist (override)
```

### Listas incluidas

| Archivo | Uso |
|---------|-----|
| `blacklists/parental.txt` | Control parental |
| `blacklists/educational.txt` | Aula de informática |
| `blacklists/doh-block.txt` | Solo bloqueo DoH |

### Múltiples listas
```bash
sudo python3 dns_traffic_controller.py -v -y \
    --blacklist blacklists/parental.txt \
    blacklists/educational.txt \
    blacklists/doh-block.txt
```

---

## Logs y Persistencia

### Ubicaciones

| Tipo | Ruta |
|------|------|
| Logs | `/var/log/dns-controller/dns-controller.log` |
| IPs guardadas | `/etc/dns-controller/allowed_ips.txt` |
| DNS cache | `/etc/dns-controller/allowed_ips.txt.domains` |

### Ver logs

```bash
# Tiempo real
sudo tail -f /var/log/dns-controller/dns-controller.log

# Últimas 100 líneas
sudo tail -100 /var/log/dns-controller/dns-controller.log

# Buscar bloqueos
grep BLOCKED /var/log/dns-controller/dns-controller.log
```

---

## Comandos de Emergencia

```bash
# Liberar todo el tráfico
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F

# Script de emergencia
sudo bash reset_iptables.sh

# Ver reglas actuales
sudo iptables -L OUTPUT -n -v
sudo iptables -L FORWARD -n -v
```

---

## Instalación como Servicio (Systemd)

```bash
sudo nano /etc/systemd/system/dns-traffic-controller.service
```

Contenido:
```ini
[Unit]
Description=DNS Traffic Controller
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/dns_traffic_controller.py -v -y --blacklist /usr/local/bin/blacklists/educational.txt --router --load-ips --save-ips
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dns-traffic-controller
sudo systemctl start dns-traffic-controller
sudo systemctl status dns-traffic-controller
```

---

## Solución de Problemas

### El router no forwardea tráfico
```bash
# Verificar IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Verificar NAT
sudo iptables -t nat -L POSTROUTING -n -v

# Verificar FORWARD
sudo iptables -L FORWARD -n -v
```

### DNS no resuelve en clientes
```bash
# Ver que el script está corriendo
ps aux | grep dns_traffic_controller

# Probar DNS manualmente
nslookup google.com 192.168.100.1

# Ver logs
sudo tail -f /var/log/dns-controller/dns-controller.log
```

### Máquinas virtuales escapan al control
- VMs en modo bridge pueden evadir
- Considerar bloquear en el switch/router upstream

---

## Limitaciones

### Lo que NO puede hacer (sin proxy MITM):
- Filtrado por SNI
- Inspección de contenido HTTPS
- Bloqueo completo de CDNs compartidos

### Lo que SÍ bloquea:
- DNS tradicional (UDP 53)
- DNS sobre HTTPS (DoH)
- DNS sobre TLS (DoT)
- QUIC/HTTP3
- VPNs
- Proxies
- Túneles
- Dominios específicos

---

## Archivos Incluidos

```
dns_traffic_controller.py   # Script principal
install.sh                 # Instalador interactivo
reset_iptables.sh          # Script de emergencia
blacklists/
├── parental.txt           # Lista parental
├── educational.txt        # Lista educativa
└── doh-block.txt         # Solo DoH
```

---

## Licencia

MIT
