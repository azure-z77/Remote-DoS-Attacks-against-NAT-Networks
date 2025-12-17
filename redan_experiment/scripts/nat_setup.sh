#!/bin/bash

# NAT设备设置脚本

echo "[*] 开始配置NAT设备..."

# 设置网络接口
# ip addr add 192.168.1.2/24 dev eth0
# ip addr add 10.0.0.2/24 dev eth1

# 启用IP转发
sysctl -w net.ipv4.ip_forward=1

# 清除现有的iptables规则
iptables -t nat -F
iptables -F

# 配置iptables进行NAT

# 查找 internal_net 对应的 interface
IN_IF=$(ip -o addr show | grep 192.168.1.2 | awk '{print $2}')
# 查找 external_net 对应的 interface
OUT_IF=$(ip -o addr show | grep 10.0.0.2 | awk '{print $2}')

echo "[nat] internal IF: $IN_IF"
echo "[nat] external IF: $OUT_IF"

# NAT 出口
iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE

# 转发规则
iptables -A FORWARD -i "$IN_IF" -o "$OUT_IF" -j ACCEPT
iptables -A FORWARD -i "$OUT_IF" -o "$IN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

# iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
# iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
# iptables -A FORWARD -i eth1 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# 配置默认路由
# ip route add default via 10.0.0.1 dev eth1

# 启动流量捕获
tcpdump -i any -w /logs/nat_traffic.pcap &

echo "[+] NAT设备配置完成"
echo "[*] NAT网关: 192.168.1.2 (内部), 10.0.0.2 (外部)"

# 保持容器运行
tail -f /dev/null