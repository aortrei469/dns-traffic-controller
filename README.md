# DNS Traffic Controller

**Control parental y de red avanzado con protección contra evasión**

Sistema de filtrado de tráfico de red que restringe el acceso a internet permitiendo solo:
- Direcciones IP privadas locales
- IPs resueltas vía DNS controlado
- Listas negras personalizables
- Bloqueo completo de DoH, DoT, QUIC, VPNs y túneles

## Características

- 🎯 **Sniffing DNS** - Detecta y resuelve consultas automáticamente
- 🔒 **Bloqueo por defecto** - Política OUTPUT DROP
- 📝 **Listas negras** - Modo parental, educativo, custom
- 🛡️ **Protección contra evasión** - Bloquea DoH, DoT, QUIC, VPNs, proxies, túneles
- ⏰ **Forzar DNS local** - Modifica configuración del sistema
- 🌐 **Modo Router** - Funciona como gateway
- 📊 **Logs persistentes** - Guardados en `/var/log/dns-controller/`
- 💾 **Persistencia de IPs** - Guarda y carga IPs aprendidas entre sesiones

## Casos de Uso

### 1. PC Individual (Control Parental)
```
[PC Niño] → [DNS Controller] → [Router] → [Internet]
```
Para controlar el ordenador de un niño.

### 2. Router de Aula
```
[PCs Aula] → [PC Router] → [Mikrotik] → [ISP]
```
Para controlar toda una red de aula.

---

## Instalación

### Opción A: Usar el instalador interactivo (recomendado)

```bash
cd /home/admon/opencodeDNS
sudo ./install.sh
```

El instalador te permitirá:
- Elegir perfil (parental/educativo)
- Seleccionar servidor DNS
- Configurar opciones
- Instalar como servicio

### Opción B: Instalación manual

```bash
# Instalar dependencias
sudo apt update
sudo apt install python3-pip iptables
sudo pip3 install scapy

# Copiar script
sudo cp dns_traffic_controller.py /usr/local/bin/
sudo chmod +x /usr/local/bin/dns_traffic_controller.py
```

---

## Guía de Prueba - Ejemplos por Orden

### 1. Prueba básica (sin blacklist)

```bash
sudo python3 dns_traffic_controller.py -v -y
```

Esto ejecuta el controlador con:
- ✅ Bloqueo de DoH/DoT/QUIC
- ✅ Bloqueo de VPNs y proxies
- ✅ Solo permite DNS (puerto 53)
- ⏭️ **Siguiente paso: ejecutar con blacklist**

---

### 2. Modo Parental (con lista negra)

```bash
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt
```

Esto añade:
- ❌ Bloquea redes sociales (Facebook, Instagram, Twitter, TikTok, etc.)
- ❌ Bloquea streaming (YouTube, Netflix, Twitch)
- ❌ Bloquea juegos (Steam, Epic, Roblox)

---

### 3. Con forzar DNS local

```bash
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --force-dns
```

Esto fuerza al sistema a usar el DNS configurado.

---

### 4. Guardar IPs aprendidas (al salir)

```bash
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --save-ips
```

Al salir (Ctrl+C), guardará las IPs aprendidas en:
- `/etc/dns-controller/allowed_ips.txt`
- `/etc/dns-controller/allowed_ips.txt.domains`

---

### 5. Cargar IPs guardadas (al iniciar)

```bash
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --load-ips
```

Carga las IPs de la sesión anterior para no tener que volver a resolverlas.

---

### 6. Sesión completa (cargar + guardar)

```bash
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt --load-ips --save-ips
```

---

### 7. Modo Educativo

```bash
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/educational.txt
```

---

### 8. Solo bloqueo DoH/QUIC/VPN (sin blacklist)

```bash
sudo python3 dns_traffic_controller.py -v -y
```

Ya incluye el bloqueo por defecto.

---

### 9. Modo Router (para aula)

```bash
sudo python3 dns_traffic_controller.py -v -y --blacklist blacklists/educational.txt --router
```

Esto habilita:
- IP forwarding
- Forward de tráfico
- Permite actuar como gateway

---

### 10. Ver logs

```bash
# Ver logs en tiempo real
sudo tail -f /var/log/dns-controller/dns-controller.log

# Ver últimos 50 líneas
sudo tail -50 /var/log/dns-controller/dns-controller.log
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
- `blacklists/parental.txt` - Modo parental
- `blacklists/educational.txt` - Modo educativo
- `blacklists/doh-block.txt` - Solo DoH

---

## Comandos de Emergencia

```bash
# Liberar todo el tráfico
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F

# Script de emergencia
sudo bash reset_iptables.sh

# Ver reglas actuales
sudo iptables -L OUTPUT -n -v
```

---

## Archivos

```
dns_traffic_controller.py   # Script principal
install.sh                 # Instalador interactivo
blacklists/
├── parental.txt           # Lista parental
├── educational.txt        # Lista educativa
└── doh-block.txt         # Bloqueo DoH
```

---

## Ubicaciones

| Tipo | Ruta |
|------|------|
| Logs | `/var/log/dns-controller/dns-controller.log` |
| IPs guardadas | `/etc/dns-controller/allowed_ips.txt` |
| DNS cache | `/etc/dns-controller/allowed_ips.txt.domains` |
| Script | `/usr/local/bin/dns_traffic_controller.py` |

---

## Limitaciones

### Lo que NO puede hacer (sin proxy MITM):
- ❌ Filtrado por SNI
- ❌ Inspección de contenido HTTPS
- ❌ Bloqueo completo de CDNs compartidos

### Lo que SÍ bloquea:
- ✅ DNS tradicional (UDP 53)
- ✅ DNS sobre HTTPS (DoH)
- ✅ DNS sobre TLS (DoT)
- ✅ QUIC/HTTP3
- ✅ VPNs
- ✅ Proxies
- ✅ Túneles
- ✅ Dominios específicos

---

## Licencia

MIT
