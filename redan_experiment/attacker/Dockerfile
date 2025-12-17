FROM ubuntu:20.04

# 避免交互式配置
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iputils-ping \
    tcpdump \
    net-tools \
    nmap \
    hping3 \
    curl \
    wget \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
RUN pip3 install scapy matplotlib numpy pandas requests

# 创建攻击工具目录
RUN mkdir -p /attack_tools

WORKDIR /attack_tools

CMD ["/bin/bash"]