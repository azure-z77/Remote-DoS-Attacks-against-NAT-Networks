# ReDAN实验快速开始指南

## 环境要求

- Docker 和 Docker Compose
- Linux/macOS 系统（推荐）
- 至少 4GB 内存
- 网络连接（用于下载Docker镜像）

## 快速开始

### 1. 准备实验环境

```bash
# 进入实验文件夹
cd redan_experiment
```

### 2. 启动实验环境

```bash
# 设置脚本权限
chmod +x start_experiment.sh scripts/*.sh scripts/*.py

# 启动实验
./start_experiment.sh
```

### 3. 执行实验步骤

#### 步骤1：分别在server端和client启动脚本

```bash
# 在server container中执行
docker exec -it server_container bash
python3 /scripts/server.py

# 在client container中执行
docker exec -it client_container bash
python3 /scripts/client.py

#接着按照脚本的输出提示选择即可
```





### 4. 监控实验过程

```bash
# 查看实时流量
docker exec -it nat_container tcpdump -i any

# 查看系统指标
docker exec -it client_container tail -f /logs/metrics.log

# 查看连接状态
docker exec -it client_container tail -f /logs/connections.log
```

### 5. 常用命令

```bash
# 查看容器状态
docker-compose ps

# 进入特定容器
docker exec -it [container_name] bash

# 查看容器日志
docker logs [container_name]

# 停止实验
docker-compose down

# 清理环境
docker-compose down -v

# 查看nat表连接
conntrack -L

# 查看通往某条路的path MTU(such as,在NAT上查看通向server的PMTU)
ip route get 10.0.0.10

# 查看网卡上MTU
ifconfig
```

## 容器角色说明

| 容器名称 | IP地址 | 角色 |
|---------|--------|------|
| nat_container | 192.168.1.1, 10.0.0.2 | NAT设备/路由器 |
| client_container | 192.168.1.100 | 内部客户端 |
| server_container | 10.0.0.10 | 外部服务器 |
| attacker_container | 10.0.0.100 | 攻击者 |

## 服务端口映射

- HTTP: localhost:8080 → server:80
- SSH: localhost:2222 → server:22  
- FTP: localhost:2121 → server:21

## 故障排除

### 容器启动失败
```bash
# 检查Docker服务
sudo systemctl status docker

# 查看详细错误
docker-compose logs
```

### 网络连接问题
```bash
# 检查网络配置
docker network ls
docker network inspect redan_experiment_internal_net
docker network inspect redan_experiment_external_net
```

### 脚本执行错误
```bash
# 检查脚本权限
ls -la scripts/

# 手动设置权限
chmod +x scripts/*.sh scripts/*.py
```

## 安全注意事项

1. **隔离环境**：确保在隔离的测试环境中运行实验
2. **合法用途**：仅用于学术研究和教育目的
3. **授权测试**：在对任何网络进行测试前获得适当授权
4. **数据保护**：实验数据可能包含敏感信息，请妥善处理

## 进一步探索

1. **测试不同防御**：尝试各种防御措施的效果
2. **扩展实验**：添加更多类型的NAT设备
3. **性能优化**：优化攻击和检测算法的性能

## 实验完成后的清理

```bash
# 停止所有容器
docker-compose down

# 删除网络和数据卷
docker-compose down -v

# 清理Docker镜像（可选）
docker image prune -f
```

---

**注意**：本实验仅用于学术研究和教育目的。请确保在获得适当授权的环境中进行测试，并遵循负责任的漏洞披露原则。