#!/bin/bash

VERSION="1.0.0"
INSTALL_DIR="/usr/local/bin/dns-controller"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/dns-controller"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    clear
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}  DNS Traffic Controller - Installer v${VERSION}${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script debe ejecutarse como root"
        echo "Ejemplo: sudo $0"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
    else
        OS="unknown"
    fi
    
    case $OS in
        ubuntu|debian|linuxmint|pop)
            PACKAGE_MANAGER="apt"
            ;;
        fedora|centos|rhel|rocky|alma)
            PACKAGE_MANAGER="yum"
            ;;
        arch|manjaro)
            PACKAGE_MANAGER="pacman"
            ;;
        *)
            print_warning "SO no detectado. Usando apt por defecto."
            PACKAGE_MANAGER="apt"
            ;;
    esac
    
    print_status "Sistema detectado: $OS ($PACKAGE_MANAGER)"
}

install_dependencies() {
    echo ""
    echo -e "${YELLOW}Instalando dependencias...${NC}"
    
    case $PACKAGE_MANAGER in
        apt)
            apt update -qq
            apt install -y python3 python3-pip iptables tcpdump
            ;;
        yum)
            yum install -y python3 python3-pip iptables tcpdump
            ;;
        pacman)
            pacman -Sy --noconfirm python python-pip iptables tcpdump
            ;;
    esac
    
    print_status "Instalando scapy..."
    pip3 install scapy --quiet
    
    print_status "Dependencias instaladas"
}

create_directories() {
    echo ""
    echo -e "${YELLOW}Creando directorios...${NC}"
    
    mkdir -p "$INSTALL_DIR/blacklists"
    mkdir -p "$CONFIG_DIR"
    mkdir -p /var/log/dns-controller
    
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$CONFIG_DIR"
    
    print_status "Directorios creados en $INSTALL_DIR"
}

copy_files() {
    echo ""
    echo -e "${YELLOW}Copiando archivos...${NC}"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    cp "$SCRIPT_DIR/dns_traffic_controller.py" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/dns_traffic_controller.py"
    
    if [[ -d "$SCRIPT_DIR/blacklists" ]]; then
        cp -r "$SCRIPT_DIR/blacklists/"* "$INSTALL_DIR/blacklists/"
    fi
    
    cp "$SCRIPT_DIR/reset_iptables.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/reset_iptables.sh"
    
    print_status "Archivos copiados"
}

download_blacklists() {
    echo ""
    echo -e "${YELLOW}¿Descargar listas negras públicas? (recomendado)${NC}"
    echo "  1) Sí, descargar listas básicas"
    echo "  2) No, usar solo listas incluidas"
    echo -n "Opción [1]: "
    read -r download_choice
    
    if [[ "$download_choice" == "1" ]]; then
        print_status "Descargando listas..."
        
        cd "$INSTALL_DIR/blacklists" || exit
        
        if command -v wget &> /dev/null; then
            wget -q "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -O stevenblack_hosts.txt 2>/dev/null || true
            print_status "Descargada lista StevenBlack"
        fi
        
        print_status "Listas descargadas"
    fi
}

configure_options() {
    echo ""
    echo -e "${YELLOW}=== Configuración ===${NC}"
    echo ""
    
    echo "Selecciona el perfil:"
    echo "  1) Parental (redes sociales, streaming, juegos)"
    echo "  2) Educativo (bloquea distractores)"
    echo "  3) Personalizado"
    echo "  4) Solo bloquear DoH/QUIC/VPN"
    echo -n "Opción [1]: "
    read -r profile_choice
    
    case $profile_choice in
        1)
            BLACKLIST_FILE="$INSTALL_DIR/blacklists/parental.txt"
            PROFILE_NAME="parental"
            ;;
        2)
            BLACKLIST_FILE="$INSTALL_DIR/blacklists/educational.txt"
            PROFILE_NAME="educational"
            ;;
        3)
            echo -n "Ruta del archivo de lista negra: "
            read -r BLACKLIST_FILE
            PROFILE_NAME="custom"
            ;;
        4)
            BLACKLIST_FILE=""
            PROFILE_NAME="minimal"
            ;;
        *)
            BLACKLIST_FILE="$INSTALL_DIR/blacklists/parental.txt"
            PROFILE_NAME="parental"
            ;;
    esac
    
    echo ""
    echo "Selecciona el servidor DNS:"
    echo "  1) OpenDNS (208.67.222.222 - recomendado)"
    echo "  2) Cloudflare (1.1.1.1)"
    echo "  3) Google (8.8.8.8)"
    echo "  4) Quad9 (9.9.9.9)"
    echo -n "Opción [1]: "
    read -r dns_choice
    
    case $dns_choice in
        1)
            DNS_SERVERS="208.67.222.222 208.67.220.220"
            ;;
        2)
            DNS_SERVERS="1.1.1.1 1.0.0.1"
            ;;
        3)
            DNS_SERVERS="8.8.8.8 8.8.4.4"
            ;;
        4)
            DNS_SERVERS="9.9.9.9 149.112.112.112"
            ;;
        *)
            DNS_SERVERS="208.67.222.222 208.67.220.220"
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Opciones adicionales:${NC}"
    echo -n "  ¿Forzar DNS local? (s/N): "
    read -r force_dns
    if [[ "$force_dns" =~ ^[Ss]$ ]]; then
        FORCE_DNS="--force-dns"
    else
        FORCE_DNS=""
    fi
    
    echo -n "  ¿Iniciar automáticamente al arranque? (S/n): "
    read -r autostart
    if [[ "$autostart" =~ ^[Nn]$ ]]; then
        AUTOSTART="no"
    else
        AUTOSTART="yes"
    fi
}

create_service() {
    echo ""
    echo -e "${YELLOW}Creando servicio systemd...${NC}"
    
    BLACKLIST_ARG=""
    if [[ -n "$BLACKLIST_FILE" && "$PROFILE_NAME" != "minimal" ]]; then
        BLACKLIST_ARG="--blacklist $BLACKLIST_FILE"
    fi
    
    EXEC_LINE="$INSTALL_DIR/dns_traffic_controller.py -v -y $BLACKLIST_ARG --dns $DNS_SERVERS $FORCE_DNS $ROUTER_MODE"
    
    cat > "$SYSTEMD_DIR/dns-traffic-controller.service" << EOF
[Unit]
Description=DNS Traffic Controller - $PROFILE_NAME profile
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$EXEC_LINE
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "$SYSTEMD_DIR/dns-traffic-controller.service"
    
    print_status "Servicio creado"
}

create_uninstaller() {
    cat > "$INSTALL_DIR/uninstall.sh" << 'UNINSTALL_EOF'
#!/bin/bash

echo "Desinstalando DNS Traffic Controller..."

systemctl stop dns-traffic-controller 2>/dev/null
systemctl disable dns-traffic-controller 2>/dev/null
rm -f /etc/systemd/system/dns-traffic-controller.service
systemctl daemon-reload

rm -rf /usr/local/bin/dns-controller
rm -rf /etc/dns-controller

iptables -P OUTPUT ACCEPT
iptables -F

echo "Desinstalación completada"
UNINSTALL_EOF
    
    chmod +x "$INSTALL_DIR/uninstall.sh"
    print_status "Uninstaller creado"
}

create_helper_scripts() {
    cat > /usr/local/bin/dns-allow << 'EOF'
#!/bin/bash
echo "Añadir IP permitida temporalmente"
if [[ -z "$1" ]]; then
    echo "Uso: dns-allow <IP>"
    exit 1
fi
iptables -I OUTPUT -d "$1" -j ACCEPT
echo "IP $1 permitida"
EOF
    chmod +x /usr/local/bin/dns-allow
    
    cat > /usr/local/bin/dns-block << 'EOF'
#!/bin/bash
echo "Bloquear IP"
if [[ -z "$1" ]]; then
    echo "Uso: dns-block <IP>"
    exit 1
fi
iptables -I OUTPUT -d "$1" -j DROP
echo "IP $1 bloqueada"
EOF
    chmod +x /usr/local/bin/dns-block
    
    cat > /usr/local/bin/dns-status << 'EOF'
#!/bin/bash
echo "=== Estado del DNS Controller ==="
echo ""
echo "--- Reglas iptables OUTPUT ---"
iptables -L OUTPUT -n --line-numbers | head -30
echo ""
echo "--- Servicios activos ---"
systemctl status dns-traffic-controller --no-pager || echo "Servicio no activo"
EOF
    chmod +x /usr/local/bin/dns-status
    
    print_status "Scripts helper creados"
}

start_service() {
    echo ""
    
    if [[ "$AUTOSTART" == "yes" ]]; then
        print_status "Iniciando servicio..."
        systemctl daemon-reload
        systemctl enable dns-traffic-controller
        systemctl start dns-traffic-controller
        
        sleep 2
        
        if systemctl is-active --quiet dns-traffic-controller; then
            print_status "Servicio iniciado correctamente"
        else
            print_warning "El servicio no pudo iniciarse. Verifica con: sudo journalctl -u dns-traffic-controller"
        fi
    else
        print_warning "Servicio no configurado para iniciar automáticamente"
        echo "Para iniciar manualmente: sudo systemctl start dns-traffic-controller"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  Instalación completada${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo "Archivos instalados en: $INSTALL_DIR"
    echo "Configuración: $CONFIG_DIR"
    echo ""
    echo "Comandos útiles:"
    echo "  dns-status          - Ver estado y reglas"
    echo "  dns-allow <IP>      - Permitir IP temporalmente"
    echo "  dns-block <IP>      - Bloquear IP"
    echo "  $INSTALL_DIR/reset_iptables.sh - Resetear reglas"
    echo "  $INSTALL_DIR/uninstall.sh      - Desinstalar"
    echo ""
    echo "Servicio systemd:"
    echo "  sudo systemctl start dns-traffic-controller"
    echo "  sudo systemctl stop dns-traffic-controller"
    echo "  sudo systemctl status dns-traffic-controller"
    echo "  sudo journalctl -u dns-traffic-controller -f"
    echo ""
    echo "Perfil: $PROFILE_NAME"
    echo "DNS: $DNS_SERVERS"
    echo ""
}

main() {
    print_header
    check_root
    detect_os
    install_dependencies
    create_directories
    copy_files
    download_blacklists
    configure_options
    create_service
    create_uninstaller
    create_helper_scripts
    start_service
    print_summary
}

main "$@"
