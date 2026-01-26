# SONiC Telemetry 监控系统

基于 gnmic + Prometheus + Grafana 的 SONiC 交换机监控系统。
详细的部署过程和细节，可以参考我的Blog：

https://www.zhaocs.info/sonic-telemetry-deployment.html

## 特性

- 支持多交换机、多SONiC版本
- 每交换机独立订阅，避免OID冲突
- 支持每台交换机独立认证
- 自动OID发现和配置生成
- 配置变更自动检测和差异显示

## 快速开始

```bash
# 1. 编辑交换机列表
vi config/switches.conf

# 2. 编辑认证信息
vi config/settings.conf

# 3. 运行配置生成脚本
./scripts/auto-refresh.sh

# 4. 启动服务
docker compose up -d

# 5. 访问Grafana: http://localhost:3000 (admin/admin)
```

## 日常维护

```bash
# 添加新交换机
vi config/switches.conf
./scripts/auto-refresh.sh
docker compose restart gnmic prometheus

# 交换机重启后OID变化
./scripts/auto-refresh.sh -f
docker compose restart gnmic prometheus
```

## 目录结构

```
sonic-telemetry/
├── config/
│   ├── switches.conf       # 交换机列表
│   ├── settings.conf       # 全局设置
│   └── modules/            # Counter模块配置
├── scripts/
│   └── auto-refresh.sh     # 配置生成脚本
├── gnmic/                  # gnmic配置（自动生成）
├── prometheus/             # prometheus配置（自动生成）
├── grafana/
├── cache/                  # OID缓存
├── backup/                 # 配置备份
├── logs/                   # 脚本日志
└── docker-compose.yml
```
