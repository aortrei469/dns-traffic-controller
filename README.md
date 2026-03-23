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

Para un router/PC gateway usando **ipset** + **iptables**.

Usa ipset para gestionar IPs разрешонные dinámicamente - mucho más eficiente que iptables puro.

### Topología

```
[Internet] → [Router] → [LAN] → [Clientes]
                  ↑
            dns_router_controller.py
```

### Uso

```bash
# Requiere especificar la interfaz LAN
sudo python3 dns_router_controller.py -i eth1 -y
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `-i INTERFAZ` | **Requerido** - Interfaz LAN a filtrar |
| `-v` | Logs detallados |
| `-y` | Saltar confirmación |
| `--dns IP` | Servidores DNS |

### Cómo funciona

1. Captura consultas DNS en la interfaz LAN
2. Añade IPs resueltas a ipset `dns_allowed`
3. Bloquea tráfico FORWARD hacia IPs no разрешонные

### Reglas aplicadas

```bash
# Permitir DNS
iptables -A FORWARD -p udp --dport 53 -j ACCEPT

# Permitir conexiones establecidas
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Permitir redes privadas
iptables -A FORWARD -d 192.168.0.0/16 -j ACCEPT
iptables -A FORWARD -d 10.0.0.0/8 -j ACCEPT
iptables -A FORWARD -d 172.16.0.0/12 -j ACCEPT

# Bloquear no разрешонные (solo en LAN especificada)
iptables -A FORWARD -i eth1 -m set ! --match-set dns_allowed dst -j DROP
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
| Método | iptables OUTPUT | iptables FORWARD + ipset |
| Eficiencia | Media | Alta (ipset) |
| Interfaz específica | No | Sí (`-i`) |
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