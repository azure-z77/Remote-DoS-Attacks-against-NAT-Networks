#!/bin/bash

# 服务器设置脚本

echo "[*] 开始配置服务器..."

# 启动Apache服务
service apache2 start

# 启动SSH服务
service ssh start

# 配置并启动FTP服务
cat > /etc/vsftpd.conf << 'EOF'
listen=YES
anonymous_enable=YES
anon_root=/home/ftp
write_enable=NO
anon_upload_enable=NO
anon_mkdir_write_enable=NO
local_enable=NO
pam_service_name=vsftpd
EOF

# 创建FTP测试文件
mkdir -p /home/ftp
echo "This is a test file for FTP" > /home/ftp/test.txt

service vsftpd start

# 启动流量捕获
tcpdump -i any -w /logs/server_traffic.pcap &

echo "[+] 服务器配置完成"
echo "[*] HTTP服务: http://10.0.0.10:80"
echo "[*] SSH服务: 10.0.0.10:22"
echo "[*] FTP服务: 10.0.0.10:21"

# 显示服务状态
service apache2 status
service ssh status
service vsftpd status

# 保持容器运行
tail -f /dev/null