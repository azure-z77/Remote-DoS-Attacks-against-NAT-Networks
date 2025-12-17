#!/usr/bin/env python3
"""
NAT设备识别工具
利用PMTUD侧信道识别NAT设备
"""

import scapy.all as scapy
import time
import socket
import threading
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.http import HTTPRequest
import requests
import random

class NATIdentifier:
    def __init__(self, target_ip, server_ip):
        self.target_ip = target_ip
        self.server_ip = server_ip
        self.results = []
        
    def create_icmp_fragmentation_needed(self, target_ip, mtu=1200):
        """创建ICMP Fragmentation Needed包"""
        icmp_packet = IP(dst=target_ip)/ICMP(type=3, code=4)/scapy.Raw(load=scapy.RandString(size=mtu))
        return icmp_packet
    
    def send_ping_test(self, target_ip, size=1500):
        """发送Ping测试包"""
        ping_packet = IP(dst=target_ip, flags='DF')/ICMP()/scapy.Raw(load=scapy.RandString(size=size-28))
        return ping_packet
    
    def identify_nat_device(self):
        """
        识别NAT设备
        返回: True表示是NAT设备, False表示不是NAT设备
        """
        print(f"[*] 正在识别 {self.target_ip} 是否为NAT设备...")
        
        # 1. 发送ICMP Fragmentation Needed包来降低路径MTU
        print("[1] 发送ICMP Fragmentation Needed包...")
        icmp_packet = self.create_icmp_fragmentation_needed(self.target_ip, mtu=1200)
        scapy.send(icmp_packet, verbose=False)
        
        # 等待一段时间让MTU更新生效
        time.sleep(2)
        
        # 2. 发送大尺寸的Ping包进行测试
        print("[2] 发送大尺寸Ping包进行测试...")
        responses = []
        
        for i in range(10):
            ping_packet = self.send_ping_test(self.target_ip, size=1500)
            response = scapy.sr1(ping_packet, timeout=3, verbose=False)
            
            if response:
                response_size = len(response)
                responses.append(response_size)
                print(f"    响应 {i+1}: 大小 {response_size} 字节")
            else:
                print(f"    响应 {i+1}: 超时")
                responses.append(0)
            
            time.sleep(0.5)
        
        # 3. 分析响应模式
        print("[3] 分析响应模式...")
        valid_responses = [r for r in responses if r > 0]
        
        if not valid_responses:
            print("[-] 无法获得有效响应")
            return False
        
        avg_size = sum(valid_responses) / len(valid_responses)
        print(f"    平均响应大小: {avg_size} 字节")
        
        # 如果响应大小接近原始大小，说明不是NAT设备
        # 如果响应大小被限制，说明是NAT设备
        if avg_size > 1400:
            print(f"[-] {self.target_ip} 看起来不是NAT设备")
            return False
        else:
            print(f"[+] {self.target_ip} 可能是NAT设备")
            return True
    
    def test_with_http(self):
        """通过HTTP测试NAT识别"""
        print(f"[*] 通过HTTP测试NAT识别...")
        
        try:
            # 尝试访问HTTP服务来触发PMTUD
            response = requests.get(f'http://{self.server_ip}', timeout=10)
            print(f"    HTTP响应状态: {response.status_code}")
            
            # 然后立即进行Ping测试
            return self.identify_nat_device()
            
        except Exception as e:
            print(f"[-] HTTP测试失败: {e}")
            return False

def main():
    # 测试目标
    target_ip = "10.0.0.2"  # 客户端IP
    server_ip = "10.0.0.10"      # 服务器IP
    
    # 创建识别器
    identifier = NATIdentifier(target_ip, server_ip)
    
    # 执行NAT识别
    is_nat = identifier.identify_nat_device()
    
    if is_nat:
        print(f"\n[+] 确认 {target_ip} 是NAT设备后的客户端")
        
        # 保存识别结果
        result = {
            'target_ip': target_ip,
            'server_ip': server_ip,
            'is_nat': True,
            'timestamp': time.time(),
            'method': 'pmtud_side_channel'
        }
        
        with open('/output/nat_identification_result.json', 'w') as f:
            import json
            json.dump(result, f, indent=2)
            
        print("[*] 识别结果已保存到 /output/nat_identification_result.json")
    else:
        print(f"\n[-] {target_ip} 可能不是NAT设备后的客户端")

if __name__ == "__main__":
    main()