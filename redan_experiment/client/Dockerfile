FROM ubuntu:20.04

# 避免交互式配置
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    iputils-ping \
    openssh-client \
    ftp \
    tcpdump \
    python3 \
    python3-pip \
    net-tools \
    iproute2 \
    telnet \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
RUN pip3 install requests scapy

CMD ["/bin/bash"]