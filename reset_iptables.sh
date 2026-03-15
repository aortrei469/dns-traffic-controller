#!/bin/bash
# Reset iptables rules - Emergency script

echo "Resetting iptables rules..."
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
echo "Iptables rules reset to default (ACCEPT)"
