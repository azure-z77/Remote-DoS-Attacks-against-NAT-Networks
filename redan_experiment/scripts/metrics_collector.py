#!/usr/bin/env python3
"""
性能指标收集器
收集系统性能数据用于分析攻击效果
"""

import psutil
import time
import json
import os
import threading
from datetime import datetime

class MetricsCollector:
    def __init__(self, output_file, interval=5):
        self.output_file = output_file
        self.interval = interval
        self.running = False
        self.collected_data = []
        
    def collect_system_metrics(self):
        """收集系统性能指标"""
        metrics = {
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_mb': psutil.virtual_memory().used / (1024 * 1024),
            'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
            'network_io': psutil.net_io_counters()._asdict(),
            'connections': self.get_network_connections(),
            'processes': self.get_process_info(),
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        }
        return metrics
    
    def get_network_connections(self):
        """获取网络连接信息"""
        connections = psutil.net_connections()
        connection_summary = {
            'total': len(connections),
            'established': 0,
            'listen': 0,
            'time_wait': 0,
            'close_wait': 0,
            'other': 0
        }
        
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                connection_summary['established'] += 1
            elif conn.status == 'LISTEN':
                connection_summary['listen'] += 1
            elif conn.status == 'TIME_WAIT':
                connection_summary['time_wait'] += 1
            elif conn.status == 'CLOSE_WAIT':
                connection_summary['close_wait'] += 1
            else:
                connection_summary['other'] += 1
        
        return connection_summary
    
    def get_process_info(self):
        """获取进程信息"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                processes.append(proc.info)
            
            # 只保留CPU使用率最高的10个进程
            processes = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:10]
            return processes
        except:
            return []
    
    def start_collection(self):
        """开始收集指标"""
        print(f"[*] 开始收集性能指标，输出到 {self.output_file}")
        print(f"[*] 收集间隔: {self.interval}秒")
        
        self.running = True
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
        while self.running:
            try:
                metrics = self.collect_system_metrics()
                self.collected_data.append(metrics)
                
                # 实时写入文件
                with open(self.output_file, 'a') as f:
                    f.write(json.dumps(metrics) + '\n')
                
                # 显示当前状态
                self.display_current_status(metrics)
                
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"[!] 收集指标时出错: {e}")
                time.sleep(self.interval)
    
    def display_current_status(self, metrics):
        """显示当前系统状态"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
              f"CPU: {metrics['cpu_percent']:5.1f}% | "
              f"内存: {metrics['memory_percent']:5.1f}% | "
              f"连接: {metrics['connections']['total']:3d} | "
              f"网络: {metrics['network_io']['bytes_sent']//1024:8d}KB sent")
    
    def stop_collection(self):
        """停止收集指标"""
        self.running = False
        print("[*] 指标收集已停止")
    
    def generate_summary(self):
        """生成数据摘要"""
        if not self.collected_data:
            return {}
        
        df = self.collected_data
        
        summary = {
            'collection_period': {
                'start': df[0]['datetime'],
                'end': df[-1]['datetime'],
                'duration_minutes': (df[-1]['timestamp'] - df[0]['timestamp']) / 60
            },
            'cpu_stats': {
                'average': sum(d['cpu_percent'] for d in df) / len(df),
                'maximum': max(d['cpu_percent'] for d in df),
                'minimum': min(d['cpu_percent'] for d in df)
            },
            'memory_stats': {
                'average': sum(d['memory_percent'] for d in df) / len(df),
                'maximum': max(d['memory_percent'] for d in df),
                'minimum': min(d['memory_percent'] for d in df)
            },
            'network_stats': {
                'total_bytes_sent': df[-1]['network_io']['bytes_sent'] - df[0]['network_io']['bytes_sent'],
                'total_bytes_recv': df[-1]['network_io']['bytes_recv'] - df[0]['network_io']['bytes_recv'],
                'peak_connections': max(d['connections']['total'] for d in df)
            }
        }
        
        return summary

class AttackEffectAnalyzer:
    def __init__(self, metrics_file):
        self.metrics_file = metrics_file
        self.data = []
        
    def load_data(self):
        """加载指标数据"""
        with open(self.metrics_file, 'r') as f:
            for line in f:
                if line.strip():
                    self.data.append(json.loads(line))
    
    def analyze_attack_effect(self):
        """分析攻击效果"""
        if not self.data:
            print("[-] 没有数据可供分析")
            return
        
        # 寻找异常模式
        connections = [d['connections']['total'] for d in self.data]
        cpu_usage = [d['cpu_percent'] for d in self.data]
        
        # 检测连接数下降
        baseline_connections = sum(connections[:10]) / 10  # 前10个值的平均值
        min_connections = min(connections)
        connection_drop = baseline_connections - min_connections
        
        # 检测CPU使用率峰值
        max_cpu = max(cpu_usage)
        avg_cpu = sum(cpu_usage) / len(cpu_usage)
        cpu_spike = max_cpu - avg_cpu
        
        analysis = {
            'baseline_connections': baseline_connections,
            'minimum_connections': min_connections,
            'connection_drop': connection_drop,
            'connection_drop_percent': (connection_drop / baseline_connections * 100) if baseline_connections > 0 else 0,
            'max_cpu_usage': max_cpu,
            'average_cpu_usage': avg_cpu,
            'cpu_spike': cpu_spike,
            'attack_detected': connection_drop > baseline_connections * 0.3  # 连接数下降超过30%
        }
        
        return analysis
    
    def generate_timeline(self):
        """生成时间线分析"""
        timeline = []
        
        for i, entry in enumerate(self.data):
            timeline.append({
                'time': i * 5,  # 假设每5秒一个数据点
                'connections': entry['connections']['total'],
                'cpu': entry['cpu_percent'],
                'memory': entry['memory_percent'],
                'network_sent': entry['network_io']['bytes_sent'],
                'network_recv': entry['network_io']['bytes_recv']
            })
        
        return timeline

def main():
    # 启动指标收集
    output_file = '/output/system_metrics.jsonl'
    interval = 5  # 5秒间隔
    
    collector = MetricsCollector(output_file, interval)
    
    try:
        collector.start_collection()
    except KeyboardInterrupt:
        print("\n[*] 用户中断收集")
        collector.stop_collection()
        
        # 生成摘要报告
        summary = collector.generate_summary()
        
        with open('/output/metrics_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        print("[*] 数据摘要已保存")
        print(f"[*] 共收集 {len(collector.collected_data)} 个数据点")

if __name__ == "__main__":
    main()