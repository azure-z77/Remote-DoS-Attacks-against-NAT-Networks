#!/usr/bin/env python3
"""
实验结果分析工具
分析ReDAN攻击的效果和影响
"""

import json
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import seaborn as sns
from collections import defaultdict
import os

# 设置matplotlib中文字体支持
from matplotlib import font_manager as fm
fm.fontManager.__init__()
cjk_list = ['CJK', 'Han', 'CN', 'TW', 'JP']
cjk_fonts = [f.name for f in fm.fontManager.ttflist if any(s.lower() in f.name.lower() for s in cjk_list)]
plt.rcParams['font.family'] = ['DejaVu Sans'] + cjk_fonts
plt.rcParams['axes.unicode_minus'] = False

class ReDANAnalyzer:
    def __init__(self, output_dir='/output'):
        self.output_dir = output_dir
        self.metrics_data = []
        self.attack_stats = {}
        self.connection_log = []
        
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        
        # 设置图表样式
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def load_data(self):
        """加载所有数据文件"""
        # 加载系统指标数据
        metrics_file = os.path.join(self.output_dir, 'system_metrics.jsonl')
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                for line in f:
                    if line.strip():
                        self.metrics_data.append(json.loads(line))
            print(f"[*] 加载了 {len(self.metrics_data)} 个系统指标数据点")
        
        # 加载攻击统计
        attack_stats_file = os.path.join(self.output_dir, 'attack_statistics.json')
        if os.path.exists(attack_stats_file):
            with open(attack_stats_file, 'r') as f:
                self.attack_stats = json.load(f)
            print(f"[*] 加载了攻击统计数据")
        
        # 加载连接监控数据
        connection_log_file = os.path.join(self.output_dir, 'connection_monitor.json')
        if os.path.exists(connection_log_file):
            with open(connection_log_file, 'r') as f:
                self.connection_log = json.load(f)
            print(f"[*] 加载了 {len(self.connection_log)} 个连接监控数据点")
    
    def analyze_system_performance(self):
        """分析系统性能影响"""
        if not self.metrics_data:
            print("[-] 没有系统指标数据可供分析")
            return
        
        # 转换为DataFrame
        df = pd.DataFrame(self.metrics_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # 创建性能分析图表
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('ReDAN攻击对系统性能的影响分析', fontsize=16, fontweight='bold')
        
        # CPU使用率
        axes[0, 0].plot(df['timestamp'], df['cpu_percent'], 'r-', linewidth=2, label='CPU使用率')
        axes[0, 0].set_title('CPU使用率变化', fontweight='bold')
        axes[0, 0].set_ylabel('CPU使用率 (%)')
        axes[0, 0].grid(True, alpha=0.3)
        axes[0, 0].legend()
        
        # 内存使用率
        axes[0, 1].plot(df['timestamp'], df['memory_percent'], 'b-', linewidth=2, label='内存使用率')
        axes[0, 1].set_title('内存使用率变化', fontweight='bold')
        axes[0, 1].set_ylabel('内存使用率 (%)')
        axes[0, 1].grid(True, alpha=0.3)
        axes[0, 1].legend()
        
        # 网络连接数
        connection_counts = [conn['total'] for conn in df['connections']]
        axes[1, 0].plot(df['timestamp'], connection_counts, 'g-', linewidth=2, label='总连接数')
        axes[1, 0].set_title('网络连接数变化', fontweight='bold')
        axes[1, 0].set_ylabel('连接数')
        axes[1, 0].grid(True, alpha=0.3)
        axes[1, 0].legend()
        
        # 网络流量
        bytes_sent = [io['bytes_sent'] for io in df['network_io']]
        bytes_recv = [io['bytes_recv'] for io in df['network_io']]
        
        axes[1, 1].plot(df['timestamp'], bytes_sent, 'orange', linewidth=2, label='发送字节数')
        axes[1, 1].plot(df['timestamp'], bytes_recv, 'purple', linewidth=2, label='接收字节数')
        axes[1, 1].set_title('网络流量变化', fontweight='bold')
        axes[1, 1].set_ylabel('字节数')
        axes[1, 1].grid(True, alpha=0.3)
        axes[1, 1].legend()
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'system_performance_analysis.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        # 计算统计数据
        stats = {
            'cpu': {
                'mean': df['cpu_percent'].mean(),
                'max': df['cpu_percent'].max(),
                'min': df['cpu_percent'].min(),
                'std': df['cpu_percent'].std()
            },
            'memory': {
                'mean': df['memory_percent'].mean(),
                'max': df['memory_percent'].max(),
                'min': df['memory_percent'].min(),
                'std': df['memory_percent'].std()
            },
            'connections': {
                'mean': np.mean(connection_counts),
                'max': np.max(connection_counts),
                'min': np.min(connection_counts),
                'std': np.std(connection_counts)
            }
        }
        
        return stats
    
    def analyze_attack_effectiveness(self):
        """分析攻击效果"""
        if not self.connection_log:
            print("[-] 没有连接监控数据可供分析")
            return
        
        # 分析连接状态变化
        df_connections = pd.DataFrame(self.connection_log)
        df_connections['timestamp'] = pd.to_datetime(df_connections['timestamp'], unit='s')
        
        # 按端口分组分析
        ports = df_connections['port'].unique()
        
        fig, axes = plt.subplots(len(ports), 1, figsize=(15, 4*len(ports)))
        if len(ports) == 1:
            axes = [axes]
        
        fig.suptitle('ReDAN攻击对不同服务连接的影响', fontsize=16, fontweight='bold')
        
        for i, port in enumerate(ports):
            port_data = df_connections[df_connections['port'] == port]
            
            # 计算连接成功率
            total_attempts = len(port_data)
            successful_connections = len(port_data[port_data['status'] == '正常'])
            success_rate = (successful_connections / total_attempts * 100) if total_attempts > 0 else 0
            
            # 绘制连接状态时间线
            status_numeric = port_data['status'].map({'正常': 1, '失败': 0, '超时': 0})
            
            axes[i].plot(port_data['timestamp'], status_numeric, 'b-', linewidth=2, 
                        label=f'端口 {port} (成功率: {success_rate:.1f}%)')
            axes[i].set_ylabel('连接状态')
            axes[i].set_ylim(-0.1, 1.1)
            axes[i].grid(True, alpha=0.3)
            axes[i].legend()
            
            # 添加攻击时间段标记（假设攻击在中间时段）
            mid_time = port_data['timestamp'].iloc[len(port_data)//2]
            axes[i].axvline(x=mid_time, color='red', linestyle='--', alpha=0.7, label='攻击时段')
        
        axes[-1].set_xlabel('时间')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'attack_effectiveness_analysis.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        return {'attack_detected': True, 'affected_ports': len(ports)}
    
    def analyze_network_traffic(self):
        """分析网络流量模式"""
        if not self.metrics_data:
            return
        
        df = pd.DataFrame(self.metrics_data)
        
        # 计算流量速率
        df['bytes_sent_rate'] = df['network_io'].apply(lambda x: x['bytes_sent'])
        df['bytes_recv_rate'] = df['network_io'].apply(lambda x: x['bytes_recv'])
        
        # 计算差分（流量速率）
        df['sent_rate'] = df['bytes_sent_rate'].diff().fillna(0)
        df['recv_rate'] = df['bytes_recv_rate'].diff().fillna(0)
        
        # 创建流量分析图表
        fig, axes = plt.subplots(2, 1, figsize=(15, 10))
        fig.suptitle('网络流量模式分析', fontsize=16, fontweight='bold')
        
        # 累积流量
        axes[0].plot(df.index, df['bytes_sent_rate'] / (1024*1024), 'r-', 
                    linewidth=2, label='发送流量 (MB)')
        axes[0].plot(df.index, df['bytes_recv_rate'] / (1024*1024), 'b-', 
                    linewidth=2, label='接收流量 (MB)')
        axes[0].set_title('累积网络流量', fontweight='bold')
        axes[0].set_ylabel('流量 (MB)')
        axes[0].grid(True, alpha=0.3)
        axes[0].legend()
        
        # 流量速率
        axes[1].plot(df.index, df['sent_rate'] / 1024, 'orange', 
                    linewidth=2, label='发送速率 (KB/s)')
        axes[1].plot(df.index, df['recv_rate'] / 1024, 'purple', 
                    linewidth=2, label='接收速率 (KB/s)')
        axes[1].set_title('网络流量速率', fontweight='bold')
        axes[1].set_ylabel('速率 (KB/s)')
        axes[1].set_xlabel('时间序列')
        axes[1].grid(True, alpha=0.3)
        axes[1].legend()
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'network_traffic_analysis.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
    
    def generate_attack_timeline(self):
        """生成攻击时间线分析"""
        if not self.metrics_data or not self.attack_stats:
            return
        
        # 创建时间线图表
        fig, ax = plt.subplots(1, 1, figsize=(15, 8))
        
        # 绘制关键指标
        df = pd.DataFrame(self.metrics_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # 标准化数据以便在同一图表上显示
        connection_counts = [conn['total'] for conn in df['connections']]
        cpu_normalized = (df['cpu_percent'] - df['cpu_percent'].min()) / (df['cpu_percent'].max() - df['cpu_percent'].min())
        memory_normalized = (df['memory_percent'] - df['memory_percent'].min()) / (df['memory_percent'].max() - df['memory_percent'].min())
        connections_normalized = (connection_counts - np.min(connection_counts)) / (np.max(connection_counts) - np.min(connection_counts))
        
        ax.plot(df['timestamp'], cpu_normalized, 'r-', linewidth=2, label='CPU使用率 (标准化)')
        ax.plot(df['timestamp'], memory_normalized, 'b-', linewidth=2, label='内存使用率 (标准化)')
        ax.plot(df['timestamp'], connections_normalized, 'g-', linewidth=2, label='连接数 (标准化)')
        
        # 标记攻击时间段
        if 'attack_info' in self.attack_stats:
            start_time = pd.to_datetime(self.attack_stats['attack_info']['start_time'], unit='s')
            end_time = pd.to_datetime(self.attack_stats['attack_info']['end_time'], unit='s')
            
            ax.axvspan(start_time, end_time, alpha=0.3, color='red', label='攻击时段')
        
        ax.set_title('ReDAN攻击时间线分析', fontsize=16, fontweight='bold')
        ax.set_ylabel('标准化指标值')
        ax.set_xlabel('时间')
        ax.grid(True, alpha=0.3)
        ax.legend()
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'attack_timeline.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
    
    def generate_comprehensive_report(self):
        """生成综合分析报告"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'experiment_summary': {
                'total_data_points': len(self.metrics_data),
                'attack_duration': self.attack_stats.get('attack_info', {}).get('duration', 0),
                'total_packets_sent': self.attack_stats.get('packets', {}).get('total_packets', 0)
            },
            'vulnerability_assessment': {},
            'attack_effectiveness': {},
            'recommendations': []
        }
        
        # 分析系统性能
        if self.metrics_data:
            system_stats = self.analyze_system_performance()
            report['vulnerability_assessment']['system_performance'] = system_stats
        
        # 分析攻击效果
        if self.connection_log:
            attack_effects = self.analyze_attack_effectiveness()
            report['attack_effectiveness'] = attack_effects
        
        # 分析网络流量
        if self.metrics_data:
            self.analyze_network_traffic()
        
        # 生成攻击时间线
        if self.metrics_data and self.attack_stats:
            self.generate_attack_timeline()
        
        # 生成建议
        report['recommendations'] = [
            "启用NAT设备的TCP序列号验证功能",
            "实施PMTUD同步机制",
            "监控异常的网络流量模式",
            "定期更新NAT设备固件",
            "实施网络分段和访问控制"
        ]
        
        # 保存报告
        report_file = os.path.join(self.output_dir, 'comprehensive_analysis_report.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"[*] 综合分析报告已生成: {report_file}")
        return report

def main():
    # 创建分析器
    analyzer = ReDANAnalyzer('/output')
    
    # 加载数据
    analyzer.load_data()
    
    # 生成综合分析报告
    report = analyzer.generate_comprehensive_report()
    
    print("[*] 分析完成")
    print(f"[*] 生成了以下图表文件:")
    print("    - system_performance_analysis.png")
    print("    - attack_effectiveness_analysis.png") 
    print("    - network_traffic_analysis.png")
    print("    - attack_timeline.png")
    print("    - comprehensive_analysis_report.json")

if __name__ == "__main__":
    main()