# DNS Traffic Controller

Dos herramientas para controlar el acceso a internet:

1. **PC Individual** - Para un solo puesto de trabajo
2. **Router Controller** - Para un router/PC gateway usando ipset

---

## Requisitos

```bash
sudo apt update
sudo apt install python3-pip iptables ipset
sudo pip3 install scapy
```

---

## 1. PC Individual (dns_traffic_controller.py)

Para controlar un solo ordenador.

### Uso

```bash
# Básico
sudo python3 dns_traffic_controller.py -v -y

# Con lista negra
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt

# Guardar IPs aprendidas
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --save-ips

# Cargar IPs al iniciar
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --load-ips
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `-v` | Logs detallados |
| `-y` | Saltar confirmación |
| `--dns IP` | Servidores DNS |
| `-b FILE` | Lista negra |
| `--force-dns` | Forzar DNS local |
| `--save-ips` | Guardar IPs al salir |
| `--load-ips` | Cargar IPs al iniciar |

---

## 2. Router Controller (dns_router_controller.py)

Para un router/PC gateway usando **ipset** + **iptables** + **DNS proxy**.

Usa un proxy DNS transparente que intercepta queries y reenvía a OpenDNS.

### Topología

```
[Cliente LAN] → [Router:53] → [Proxy:5353] → [OpenDNS]
                                        ↓
                               [ipset dns_allowed]
                                        ↓
[Cliente LAN] → [Router:FORWARD] → [IP разрешонные]
```

### Uso

```bash
# Básico (LAN only)
sudo python3 dns_router_controller.py -i eth1 -y

# Con WAN (si hay segunda interfaz)
sudo python3 dns_router_controller.py -i eth1 -w eth0 -y

# Con lista negra
sudo python3 dns_router_controller.py -i eth1 -b blacklists/parental.txt -y
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `-i INTERFAZ` | **Requerido** - Interfaz LAN |
| `-w INTERFAZ` | Interfaz WAN (opcional) |
| `-v` | Logs detallados |
| `-y` | Saltar confirmación |
| `--dns IP` | Servidores DNS (default: OpenDNS) |
| `-b FILE` | Archivo de lista negra |

### Cómo funciona

1. **REDIRECT DNS**: iptables redirige queries DNS del LAN al proxy local (puerto 5353)
2. **Proxy DNS**: Recibe queries, reenvía a OpenDNS, obtiene IPs resueltas
3. **ipset**: Añade IPs разрешонadas a `dns_allowed`
4. **FORWARD**: Permite tráfico hacia IPs en ipset, bloquea lo demás

### Reglas aplicadas

```bash
# Redirect DNS al proxy local
iptables -t nat -A PREROUTING -i eth1 -p udp --dport 53 -j REDIRECT --to-port 5353

# Permitir DNS
iptables -A FORWARD -p udp --dport 53 -j ACCEPT

# Permitir conexiones establecidas
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Permitir redes privadas
iptables -A FORWARD -d 192.168.0.0/16 -j ACCEPT
iptables -A FORWARD -d 10.0.0.0/8 -j ACCEPT
iptables -A FORWARD -d 172.16.0.0/12 -j ACCEPT

# Bloquear no разрешонные (solo en LAN)
iptables -A FORWARD -i eth1 -m set ! --match-set dns_allowed dst -j DROP
```

### Ver estado

```bash
# Ver IPs разрешонadas
ipset list dns_allowed

# Ver reglas NAT (redirect)
sudo iptables -t nat -L PREROUTING -n -v

# Ver logs de bloqueos
sudo tail -f /var/log/syslog | grep DNS-BLOCKED
```

### Ver estado

```bash
# Ver IPs разрешонные
ipset list dns_allowed

# Ver logs de bloqueos
sudo tail -f /var/log/messages | grep DNS-BLOCKED
```

---

## Comparativa

| Característica | PC Individual | Router Controller |
|----------------|---------------|-------------------|
| Objetivo | Un ordenador | Red completa |
| Método | iptables OUTPUT | DNS proxy + iptables FORWARD + ipset |
| Eficiencia | Media | Alta (ipset) |
| Interfaz específica | No | Sí (`-i`) |
| Proxy DNS | No | Sí (puerto 5353) |
| Afecta router | Sí | No |

---

## Listas Negras

Formato:
```
dominio.com              # Bloquea dominio
*.dominio.com           # Subdominios
!dominio.com            # Whitelist
```

Archivos en `blacklists/`:
- `parental.txt` - Control parental
- `educational.txt` - Educación
- `doh-block.txt` - Solo DoH

---

## Bloqueos Automáticos

- **DoH/DoT**: cloudflare-dns.com, dns.google
- **DNS sobre TLS**: Puerto 853
- **QUIC/HTTP3**: Puerto 443 UDP
- **VPNs**: OpenVPN, WireGuard, Tor, IPSec
- **Proxies**: HTTP 3128/8080, SOCKS 1080
- **Túneles**: ngrok, Cloudflare Tunnel

---

## Comandos de Emergencia

```bash
# PC Individual
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F

# Router
sudo iptables -F FORWARD
sudo ipset flush

# Script emergencia
sudo bash reset_iptables.sh
```

---

## Servicio Systemd (PC Individual)

```bash
sudo nano /etc/systemd/system/dns-controller.service
```

Contenido:
```ini
[Unit]
Description=DNS Traffic Controller
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dns_traffic_controller.py -v -y --blacklist /usr/local/bin/blacklists/parental.txt --save-ips
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable dns-controller
sudo systemctl start dns-controller
```

---

## Licencia

MIT