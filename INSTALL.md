# DNS Traffic Controller - Installation Guide

## Requisitos previos

```bash
sudo apt update
sudo apt install python3-pip iptables ipset
sudo pip3 install scapy
```

---

## Instalación PC Individual

1. Copiar el script:
```bash
sudo cp dns_traffic_controller.py /usr/local/bin/
sudo chmod +x /usr/local/bin/dns_traffic_controller.py
```

2. Probar ejecución:
```bash
sudo /usr/local/bin/dns_traffic_controller.py -v -y --blacklist blacklists/parental.txt
```

---

## Instalación Router (con ipset)

1. Copiar el script:
```bash
sudo cp dns_router_controller.py /usr/local/bin/
sudo chmod +x /usr/local/bin/dns_router_controller.py
```

2. Probar ejecución (especificando interfaz LAN):
```bash
sudo /usr/local/bin/dns_router_controller.py -i eth1 -y
```

---

## Instalación como servicio (PC Individual)

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
sudo systemctl daemon-reload
sudo systemctl enable dns-controller
sudo systemctl start dns-controller
```

---

## Opciones de línea de comandos

### PC Individual
```bash
-v, --verbose         # Mostrar logs detallados
-y, --yes           # Saltar confirmación
--dns IP            # Servidores DNS (default: OpenDNS)
-b, --blacklist     # Archivo de lista negra
--force-dns         # Forzar DNS local
--save-ips          # Guardar IPs al salir
--load-ips           # Cargar IPs al iniciar
```

### Router Controller
```bash
-i, --interface     # Interfaz LAN a monitorizar (REQUERIDO)
-v, --verbose        # Logs detallados
-y, --yes           # Saltar confirmación
--dns               # Servidores DNS
```

---

## Comandos útiles

```bash
# Ver estado del servicio
sudo systemctl status dns-controller

# Ver logs
sudo journalctl -u dns-controller -f

# Detener servicio
sudo systemctl stop dns-controller

# Reiniciar servicio
sudo systemctl restart dns-controller

# Ver IPs разрешонные (router)
ipset list dns_allowed

# Liberar reglas iptables (emergencia)
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F

# Limpiar ipset (router)
sudo ipset flush
```

---

## Notas

- Ambos scripts requieren privilegios de root
- PC Individual: affecta solo el propio equipo (OUTPUT)
- Router Controller: affecta clientes en LAN específica (FORWARD + ipset)
- Las reglas iptables persisten hasta reiniciar