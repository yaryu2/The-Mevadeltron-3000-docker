#!/bin/bash

ip link set dev eth0 address 98:98:98:44:44:44

# Add iptables to each bash
# iptables -A OUTPUT -i eth0 -j DROP
# iptables -A INPUT -i eth1 -j DROP

cd code
pip3 install -r requirements.txt
cd pc

ifconfig eth0 172.16.104.15/24 netmask 255.255.255.0 up

/bin/bash