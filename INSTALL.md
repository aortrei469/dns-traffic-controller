# DNS Traffic Controller - Installation Guide for Ubuntu

## Requisitos previos

```bash
sudo apt update
sudo apt install python3-pip iptables
sudo pip3 install scapy
```

## Instalación básica

1. Copiar el script:
```bash
sudo cp dns_traffic_controller.py /usr/local/bin/
sudo chmod +x /usr/local/bin/dns_traffic_controller.py
```

2. Probar ejecución manual:
```bash
sudo /usr/local/bin/dns_traffic_controller.py -v -y
```

## Instalación como servicio (recomendado)

1. Crear el archivo de servicio:

```bash
sudo nano /etc/systemd/system/dns-traffic-controller.service
```

Contenido:
```ini
[Unit]
Description=DNS Traffic Controller - Restrict outbound network
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/dns_traffic_controller.py -v -y --dns 208.67.222.222 208.67.220.220
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

2. Recargar systemd y habilitar el servicio:
```bash
sudo systemctl daemon-reload
sudo systemctl enable dns-traffic-controller
sudo systemctl start dns-traffic-controller
```

3. Verificar estado:
```bash
sudo systemctl status dns-traffic-controller
```

4. Ver logs:
```bash
sudo journalctl -u dns-traffic-controller -f
```

## Comandos útiles

```bash
# Ver estado del servicio
sudo systemctl status dns-traffic-controller

# Ver logs en tiempo real
sudo journalctl -u dns-traffic-controller -f

# Detener el servicio
sudo systemctl stop dns-traffic-controller

# Reiniciar el servicio
sudo systemctl restart dns-traffic-controller

# Deshabilitar al inicio
sudo systemctl disable dns-traffic-controller
```

## Liberar reglas iptables (en caso de emergencia)

```bash
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F
```

## Opciones de línea de comandos

```bash
-v, --verbose    # Mostrar IPs permitidas/bloqueadas en consola
-y, --yes        # Saltar confirmación de usuario
--dns            # Especificar servidores DNS (default: OpenDNS)
```

Ejemplo con DNS personalizado:
```bash
sudo /usr/local/bin/dns_traffic_controller.py -v -y --dns 8.8.8.8 8.8.4.4
```

## Notas

- El servicio requiere privilegios de root (usa User=root en el servicio)
- Las reglas iptables persisten hasta que se reinicien o se ejecuten:
  `sudo iptables -P OUTPUT ACCEPT`
- Para mínimo impacto, el sniffer corre en un thread separado
