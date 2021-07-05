#!/bin/bash

ip link set dev eth0 address 98:98:98:22:22:22

# Add iptables to each bash
# iptables -A OUTPUT -i eth0 -j DROP
# iptables -A INPUT -i eth1 -j DROP

cd code
pip3 install -r requirements.txt
cd pc

ifconfig eth0 172.16.101.12/24 netmask 255.255.255.0 up
ifconfig eth1 172.16.102.23/24 netmask 255.255.255.0 up
ifconfig eth2 172.16.104.16/24 netmask 255.255.255.0 up
clear
/bin/bash