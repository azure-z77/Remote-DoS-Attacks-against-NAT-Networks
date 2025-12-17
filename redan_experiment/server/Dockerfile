FROM ubuntu:20.04

# 避免交互式配置
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apache2 \
    openssh-server \
    iputils-ping \
    vsftpd \
    tcpdump \
    python3 \
    python3-pip \
    net-tools \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 配置Apache
RUN echo "<html><body><h1>ReDAN Test Server</h1><p>This is a test server for ReDAN experiments.</p></body></html>" > /var/www/html/index.html

# 配置SSH
RUN mkdir -p /var/run/sshd && \
    echo 'root:redan123' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# 配置FTP
RUN mkdir -p /home/ftp && \
    echo "Test file for FTP" > /home/ftp/test.txt

EXPOSE 22 80 21
CMD ["/bin/bash"]