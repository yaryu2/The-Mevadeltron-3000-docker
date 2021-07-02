# syntax=docker/dockerfile:1
FROM ehlers/scapy
RUN apt install iproute2 -y
RUN apt update && apt install sudo -y
RUN sudo apt install iptables -y
RUN sudo apt install python3-pip -y




# https://www.youtube.com/watch?v=3SYJQ-z4LBw&ab_channel=NextGenLearning