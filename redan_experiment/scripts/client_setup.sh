#!/bin/bash

# 客户端设置脚本

echo "[*] 开始配置客户端..."

# 设置默认路由通过NAT网关
ip route del default || true
ip route add default via 192.168.1.2

# 配置DNS解析
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# 启动流量捕获
tcpdump -i any -w /logs/client_traffic.pcap &

echo "[+] 客户端配置完成"
echo "[*] 客户端IP: 192.168.1.100"
echo "[*] 默认网关: 192.168.1.2"

# 创建测试连接脚本
cat > /scripts/test_connections.py << 'EOF'
#!/usr/bin/env python3
import requests
import time
import socket
import threading

def test_http_connection():
    """测试HTTP连接"""
    try:
        response = requests.get('http://10.0.0.10', timeout=5)
        print(f"[HTTP] 连接成功，状态码: {response.status_code}")
        return True
    except Exception as e:
        print(f"[HTTP] 连接失败: {e}")
        return False

def test_ssh_connection():
    """测试SSH连接"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('10.0.0.10', 22))
        sock.close()
        
        if result == 0:
            print("[SSH] 端口开放，连接成功")
            return True
        else:
            print("[SSH] 连接失败")
            return False
    except Exception as e:
        print(f"[SSH] 连接错误: {e}")
        return False

def continuous_test():
    """持续测试连接"""
    while True:
        print("\n[*] 执行连接测试...")
        test_http_connection()
        test_ssh_connection()
        time.sleep(10)

if __name__ == "__main__":
    continuous_test()
EOF

chmod +x /scripts/test_connections.py

# 保持容器运行
tail -f /dev/null