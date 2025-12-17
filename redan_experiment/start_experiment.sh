#!/bin/bash

# ReDAN实验启动脚本

echo "=========================================="
echo "      ReDAN攻击复现实验启动器"
echo "=========================================="
echo ""

# 检查Docker环境
echo "[*] 检查Docker环境..."
if ! command -v docker &> /dev/null; then
    echo "[-] Docker未安装，请先安装Docker"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "[-] Docker Compose未安装，请先安装Docker Compose"
    exit 1
fi

echo "[+] Docker环境检查通过"

# 创建输出目录
mkdir -p output logs configs

# 设置脚本权限
chmod +x scripts/*.sh scripts/*.py

# 启动实验环境
echo ""
echo "[*] 启动Docker容器..."
docker-compose up -d --build

# 等待容器启动
echo "[*] 等待容器启动..."
sleep 10

# 检查容器状态
echo ""
echo "[*] 检查容器状态..."
docker-compose ps

# 显示容器信息
echo ""
echo "=========================================="
echo "          实验环境信息"
echo "=========================================="
echo "网络拓扑:"
echo "  内部网络: 192.168.1.0/24"
echo "  外部网络: 10.0.0.0/24"
echo ""
echo "容器角色:"
echo "  NAT设备:    nat_container (192.168.1.2, 10.0.0.2)"
echo "  客户端:     client_container (192.168.1.100)"
echo "  服务器:     server_container (10.0.0.10)"
echo "  攻击者:     attacker_container (10.0.0.100)"
echo ""
echo "服务端口映射:"
echo "  HTTP:  localhost:8880 -> server:80"
echo "  SSH:   localhost:2222 -> server:22"
echo "  FTP:   localhost:2121 -> server:21"
echo ""

# 启动监控
echo "[*] 启动系统监控..."
docker exec client_container python3 -m pip install psutil 
docker exec client_container python3 /scripts/metrics_collector.py &
MONITOR_PID=$!

echo "[*] 监控进程PID: $MONITOR_PID"

# 显示可用命令
echo ""
echo "=========================================="
echo "          可用实验命令"
echo "=========================================="
echo "1. NAT设备识别:"
echo "   docker exec attacker_container python3 /scripts/nat_identification.py"
echo ""
echo "2. 启动ReDAN攻击:"
echo "   docker exec attacker_container python3 /scripts/redan_attack.py"
echo ""
echo "3. 在客户端测试连接:"
echo "   docker exec client_container python3 /scripts/test_connections.py"
echo ""
echo "4. 查看实时流量:"
echo "   docker exec nat_container tcpdump -i any"
echo ""
echo "5. 进入容器:"
echo "   docker exec -it nat_container bash"
echo "   docker exec -it client_container bash"
echo "   docker exec -it server_container bash"
echo "   docker exec -it attacker_container bash"
echo ""
echo "6. 停止实验:"
echo "   docker-compose down"
echo ""
echo "=========================================="
echo "实验正在进行中，按Ctrl+C停止监控"
echo "=========================================="

# 等待用户输入
trap "echo '[*] 停止监控'; kill $MONITOR_PID 2>/dev/null; exit" INT
wait $MONITOR_PID