#!/bin/bash

ip link set dev eth0 address 98:98:98:11:11:11

# Add iptables to each bash
# iptables-legacy -A OUTPUT -o eth0 -j DROP
# iptables-legacy -A INPUT -i eth1 -j DROP

cd code/pc

ifconfig eth1 172.16.101.22/24 netmask 255.255.255.0 up
clear
python3 machine1.py
/bin/bash