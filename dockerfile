# syntax=docker/dockerfile:1
FROM ehlers/scapy
COPY pc1/requirements.txt /app
RUN apt install iproute2 -y
RUN apt update && apt install sudo -y
RUN sudo apt install iptables -y
RUN sudo apt install python3-pip -y
CMD pip3 install -r /app/requirements.txt



# https://www.youtube.com/watch?v=3SYJQ-z4LBw&ab_channel=NextGenLearning