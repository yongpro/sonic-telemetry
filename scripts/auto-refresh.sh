#!/bin/bash
# ============================================================
# SONiC Telemetry 自动配置刷新脚本 v3
# 
# 改进：
# - v2: 每台交换机独立订阅，避免OID不存在导致订阅失败
# - v3: 整合服务器 RDMA 监控支持
# ============================================================

set -e

# 脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# 目录定义
CONFIG_DIR="$BASE_DIR/config"
MODULES_DIR="$CONFIG_DIR/modules"
CACHE_DIR="$BASE_DIR/cache"
BACKUP_DIR="$BASE_DIR/backup"
LOGS_DIR="$BASE_DIR/logs"
GNMIC_DIR="$BASE_DIR/gnmic"
PROMETHEUS_DIR="$BASE_DIR/prometheus"

# 日志文件
LOG_FILE="$LOGS_DIR/refresh_$(date +%Y%m%d_%H%M%S).log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 全局变量
VERBOSE=false
FORCE=false

# 交换机相关
declare -A SWITCH_STATUS
declare -A SWITCH_IPS
declare -A SWITCH_USERS
declare -A SWITCH_PASSES
declare -a ONLINE_SWITCHES

# 服务器相关 (v3 新增)
declare -A SERVER_STATUS
declare -A SERVER_IPS
declare -A SERVER_PORTS
declare -a ONLINE_SERVERS
SERVER_DEFAULT_PORT=9100

# ============================================================
# 工具函数
# ============================================================

log() {
    local level=$1
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
    
    case $level in
        INFO)  echo -e "${GREEN}✓${NC} $msg" ;;
        WARN)  echo -e "${YELLOW}⚠${NC} $msg" ;;
        ERROR) echo -e "${RED}✗${NC} $msg" ;;
        DEBUG) $VERBOSE && echo -e "${CYAN}→${NC} $msg" || true ;;
    esac
}

print_header() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_subheader() {
    echo ""
    echo -e "${CYAN}──── $1 ────${NC}"
    echo ""
}

print_box() {
    local title=$1
    local width=50
    echo ""
    echo "╔$(printf '═%.0s' $(seq 1 $width))╗"
    printf "║ %-$((width-1))s║\n" "$title"
    echo "╠$(printf '═%.0s' $(seq 1 $width))╣"
}

print_box_line() {
    local width=50
    printf "║ %-$((width-1))s║\n" "$1"
}

print_box_end() {
    local width=50
    echo "╚$(printf '═%.0s' $(seq 1 $width))╝"
}

# ============================================================
# 配置读取函数
# ============================================================

load_settings() {
    log DEBUG "加载全局设置..."
    source "$CONFIG_DIR/settings.conf"
}

load_switches() {
    log DEBUG "加载交换机列表..."
    SWITCHES=()
    
    [[ ! -f "$CONFIG_DIR/switches.conf" ]] && {
        log WARN "交换机配置文件不存在: $CONFIG_DIR/switches.conf"
        return
    }
    
    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        
        # 解析格式: 名称:IP[:用户名:密码]
        local name=$(echo "$line" | cut -d':' -f1)
        local ip=$(echo "$line" | cut -d':' -f2)
        local user=$(echo "$line" | cut -d':' -f3)
        local pass=$(echo "$line" | cut -d':' -f4)
        
        SWITCHES+=("$line")
        SWITCH_IPS[$name]=$ip
        
        # 如果没有指定用户名密码，使用全局设置
        if [[ -n "$user" && -n "$pass" ]]; then
            SWITCH_USERS[$name]=$user
            SWITCH_PASSES[$name]=$pass
        else
            SWITCH_USERS[$name]=$GNMI_USER
            SWITCH_PASSES[$name]=$GNMI_PASS
        fi
    done < "$CONFIG_DIR/switches.conf"
    log DEBUG "发现 ${#SWITCHES[@]} 台交换机"
}

# v3 新增：加载服务器列表
load_servers() {
    log DEBUG "加载服务器列表..."
    SERVERS=()
    
    [[ ! -f "$CONFIG_DIR/servers.conf" ]] && {
        log DEBUG "服务器配置文件不存在: $CONFIG_DIR/servers.conf (跳过服务器监控)"
        return
    }
    
    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        
        # 解析格式: 名称:IP[:端口]
        local name=$(echo "$line" | cut -d':' -f1)
        local ip=$(echo "$line" | cut -d':' -f2)
        local port=$(echo "$line" | cut -d':' -f3)
        
        # 默认端口
        [[ -z "$port" ]] && port=$SERVER_DEFAULT_PORT
        
        SERVERS+=("$name")
        SERVER_IPS[$name]=$ip
        SERVER_PORTS[$name]=$port
    done < "$CONFIG_DIR/servers.conf"
    log DEBUG "发现 ${#SERVERS[@]} 台服务器"
}

load_module_config() {
    local module=$1
    local config_file="$MODULES_DIR/${module}.conf"
    
    [[ ! -f "$config_file" ]] && return 1
    
    enabled=""
    name_map_path=""
    prometheus_prefix=""
    label_name=""
    name_filter=""
    extract_labels=""
    
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^#.*$ || -z "$key" || "$key" =~ ^\[.*\]$ ]] && continue
        key=$(echo "$key" | tr -d ' ')
        value=$(echo "$value" | tr -d '"' | tr -d "'")
        case "$key" in
            enabled) enabled=$value ;;
            name_map_path) name_map_path=$value ;;
            prometheus_prefix) prometheus_prefix=$value ;;
            label_name) label_name=$value ;;
            name_filter) name_filter=$value ;;
            extract_labels) extract_labels=$value ;;
        esac
    done < "$config_file"
    
    [[ "$enabled" != "true" ]] && return 1
    return 0
}

load_acl_rule_mapping() {
    local config_file="$MODULES_DIR/acl.conf"
    declare -gA ACL_RULE_MAPPING
    
    [[ ! -f "$config_file" ]] && return
    
    local in_mapping=false
    while IFS= read -r line; do
        if [[ "$line" == "[rule_mapping]" ]]; then
            in_mapping=true
            continue
        fi
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            in_mapping=false
            continue
        fi
        if $in_mapping && [[ "$line" =~ ^[A-Za-z_0-9]+=.+$ ]]; then
            local rule_name=$(echo "$line" | cut -d'=' -f1)
            local display_name=$(echo "$line" | cut -d'=' -f2)
            ACL_RULE_MAPPING[$rule_name]=$display_name
        fi
    done < "$config_file"
}

# ============================================================
# 连通性检查
# ============================================================

check_switch_connectivity() {
    print_subheader "交换机连通性检查"
    
    local online_count=0
    local offline_count=0
    ONLINE_SWITCHES=()
    
    for switch in "${SWITCHES[@]}"; do
        local name=$(echo "$switch" | cut -d':' -f1)
        local ip=${SWITCH_IPS[$name]}
        
        if timeout $GNMI_TIMEOUT bash -c "echo >/dev/tcp/$ip/$GNMI_PORT" 2>/dev/null; then
            SWITCH_STATUS[$name]="online"
            ONLINE_SWITCHES+=("$name")
            log INFO "$name ($ip) - 在线"
            ((online_count++)) || true
        else
            SWITCH_STATUS[$name]="offline"
            log WARN "$name ($ip) - 离线，跳过"
            ((offline_count++)) || true
        fi
    done
    
    echo ""
    echo "  交换机: 在线 $online_count, 离线 $offline_count"
}

# v3 新增：检查服务器连通性
check_server_connectivity() {
    [[ ${#SERVERS[@]} -eq 0 ]] && return
    
    print_subheader "服务器连通性检查"
    
    local online_count=0
    local offline_count=0
    ONLINE_SERVERS=()
    
    for name in "${SERVERS[@]}"; do
        local ip=${SERVER_IPS[$name]}
        local port=${SERVER_PORTS[$name]}
        
        if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            SERVER_STATUS[$name]="online"
            ONLINE_SERVERS+=("$name")
            log INFO "$name ($ip:$port) - 在线"
            ((online_count++)) || true
        else
            SERVER_STATUS[$name]="offline"
            log WARN "$name ($ip:$port) - 离线，跳过"
            ((offline_count++)) || true
        fi
    done
    
    echo ""
    echo "  服务器: 在线 $online_count, 离线 $offline_count"
}

# 统一的连通性检查入口
check_connectivity() {
    print_header "1/4 检查连通性"
    
    check_switch_connectivity
    check_server_connectivity
}

# ============================================================
# OID收集函数 - 每交换机独立收集
# ============================================================

collect_oids_for_switch() {
    local switch_name=$1
    local module=$2
    local ip=${SWITCH_IPS[$switch_name]}
    local user=${SWITCH_USERS[$switch_name]}
    local pass=${SWITCH_PASSES[$switch_name]}
    
    local switch_cache_dir="$CACHE_DIR/$switch_name"
    mkdir -p "$switch_cache_dir"
    
    local oids_file="$switch_cache_dir/${module}_oids_new.txt"
    local map_file="$switch_cache_dir/${module}_map_new.txt"
    
    > "$oids_file"
    > "$map_file"
    
    load_module_config "$module" || return 0
    
    # 获取NAME_MAP（使用该交换机的认证信息）
    local result=$(timeout $GNMI_TIMEOUT gnmic -a ${ip}:${GNMI_PORT} --insecure \
        -u "$user" -p "$pass" \
        get --path "$name_map_path" --target COUNTERS_DB 2>/dev/null || echo "")
    
    if [[ -z "$result" ]]; then
        log DEBUG "$switch_name: 无法获取 $name_map_path"
        return 0
    fi
    
    # 解析结果
    echo "$result" | jq -r '.[] | .updates[].values | to_entries[].value | to_entries[] | "\(.key)=\(.value)"' 2>/dev/null | \
    while IFS='=' read -r entry_name entry_oid; do
        # 应用名称过滤
        if [[ -n "$name_filter" ]]; then
            echo "$entry_name" | grep -qE "$name_filter" || continue
        fi
        
        local oid=$(echo "$entry_oid" | sed 's/^oid://')
        echo "$oid" >> "$oids_file"
        echo "${entry_name}=${oid}" >> "$map_file"
    done
    
    sort -u "$oids_file" -o "$oids_file"
    sort -u "$map_file" -o "$map_file"
}

collect_all_oids() {
    print_header "2/4 收集OID"
    
    [[ ${#ONLINE_SWITCHES[@]} -eq 0 ]] && {
        log WARN "没有在线的交换机，跳过OID收集"
        return
    }
    
    # 获取所有启用的模块
    local modules=()
    for conf in "$MODULES_DIR"/*.conf; do
        [[ ! -f "$conf" ]] && continue
        local module=$(basename "$conf" .conf)
        if load_module_config "$module"; then
            modules+=("$module")
        fi
    done
    
    echo "  启用的模块: ${modules[*]}"
    echo ""
    
    # 为每台在线交换机收集每个模块的OID
    for switch_name in "${ONLINE_SWITCHES[@]}"; do
        echo -e "  ${CYAN}[$switch_name]${NC}"
        for module in "${modules[@]}"; do
            collect_oids_for_switch "$switch_name" "$module"
            
            local oids_file="$CACHE_DIR/$switch_name/${module}_oids_new.txt"
            if [[ -s "$oids_file" ]]; then
                local count=$(wc -l < "$oids_file")
                log INFO "  $module: $count 个OID"
            fi
        done
    done
    
    # 合并所有交换机的映射（用于prometheus relabel）
    for module in "${modules[@]}"; do
        local all_map_file="$CACHE_DIR/all_${module}_map_new.txt"
        > "$all_map_file"
        
        for switch_name in "${ONLINE_SWITCHES[@]}"; do
            local map_file="$CACHE_DIR/$switch_name/${module}_map_new.txt"
            [[ -s "$map_file" ]] && cat "$map_file" >> "$all_map_file"
        done
        
        sort -u "$all_map_file" -o "$all_map_file"
    done
}

# ============================================================
# 变更对比
# ============================================================

compare_and_report() {
    print_header "3/4 变更对比"
    
    local has_changes=false
    
    # 检查交换机变更
    print_subheader "交换机变更"
    
    for switch_name in "${ONLINE_SWITCHES[@]}"; do
        local switch_cache_dir="$CACHE_DIR/$switch_name"
        
        for new_file in "$switch_cache_dir"/*_oids_new.txt; do
            [[ ! -f "$new_file" ]] && continue
            
            local module=$(basename "$new_file" _oids_new.txt)
            local old_file="${new_file/_new.txt/_old.txt}"
            
            if [[ ! -f "$old_file" ]]; then
                local count=$(wc -l < "$new_file")
                [[ $count -gt 0 ]] && {
                    log INFO "$switch_name/$module: 新增 $count 个OID"
                    has_changes=true
                }
            else
                local added=$(comm -13 <(sort "$old_file") <(sort "$new_file") | wc -l)
                local removed=$(comm -23 <(sort "$old_file") <(sort "$new_file") | wc -l)
                
                if [[ $added -gt 0 || $removed -gt 0 ]]; then
                    log INFO "$switch_name/$module: +$added / -$removed"
                    has_changes=true
                fi
            fi
        done
    done
    
    # 检查服务器变更
    if [[ ${#SERVERS[@]} -gt 0 ]]; then
        print_subheader "服务器变更"
        
        local old_servers_file="$CACHE_DIR/servers_old.txt"
        local new_servers_file="$CACHE_DIR/servers_new.txt"
        
        printf '%s\n' "${ONLINE_SERVERS[@]}" | sort > "$new_servers_file"
        
        if [[ ! -f "$old_servers_file" ]]; then
            [[ ${#ONLINE_SERVERS[@]} -gt 0 ]] && {
                log INFO "新增 ${#ONLINE_SERVERS[@]} 台服务器"
                has_changes=true
            }
        else
            local added=$(comm -13 <(sort "$old_servers_file") "$new_servers_file" | wc -l)
            local removed=$(comm -23 <(sort "$old_servers_file") "$new_servers_file" | wc -l)
            
            if [[ $added -gt 0 || $removed -gt 0 ]]; then
                log INFO "服务器: +$added / -$removed"
                has_changes=true
            fi
        fi
    fi
    
    $has_changes && return 0 || return 1
}

# ============================================================
# 配置生成
# ============================================================

generate_gnmic_config() {
    log DEBUG "生成gnmic配置..."
    
    local output="$GNMIC_DIR/gnmic.yaml"
    
    cat > "$output" << EOF
# SONiC Telemetry gNMIc配置 (v3)
# 自动生成于: $(date '+%Y-%m-%d %H:%M:%S')
# 模式: 每交换机独立订阅

username: $GNMI_USER
password: $GNMI_PASS
insecure: true
timeout: ${GNMI_TIMEOUT}s
encoding: json_ietf

targets:
EOF

    # 为每台在线交换机添加target
    for switch_name in "${ONLINE_SWITCHES[@]}"; do
        local ip=${SWITCH_IPS[$switch_name]}
        local user=${SWITCH_USERS[$switch_name]}
        local pass=${SWITCH_PASSES[$switch_name]}
        
        cat >> "$output" << EOF
  ${switch_name}:
    address: ${ip}:${GNMI_PORT}
    username: $user
    password: $pass
EOF
    done

    cat >> "$output" << EOF

subscriptions:
EOF

    # 为每台交换机生成独立的订阅
    for switch_name in "${ONLINE_SWITCHES[@]}"; do
        for conf in "$MODULES_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue
            local module=$(basename "$conf" .conf)
            load_module_config "$module" || continue
            
            local oids_file="$CACHE_DIR/$switch_name/${module}_oids_new.txt"
            [[ ! -s "$oids_file" ]] && continue
            
            cat >> "$output" << EOF
  ${module}_counters_${switch_name}:
    address: ${ip}:${GNMI_PORT}
    paths:
EOF
            
            while read -r oid; do
                echo "      - \"COUNTERS:oid:${oid}\"" >> "$output"
            done < "$oids_file"
            
            cat >> "$output" << EOF
    target: COUNTERS_DB
    mode: stream
    stream-mode: sample
    sample-interval: $SAMPLE_INTERVAL

EOF
        done
    done

    cat >> "$output" << EOF
outputs:
  prometheus:
    type: prometheus
    listen: :$GNMIC_METRICS_PORT
    path: /metrics
    metric-prefix: sonic
    append-subscription-name: false
EOF

    log INFO "gnmic配置已生成"
}

generate_prometheus_config() {
    log DEBUG "生成prometheus配置..."
    
    local output="$PROMETHEUS_DIR/prometheus.yml"
    
    cat > "$output" << EOF
# SONiC Telemetry + Server RDMA Prometheus配置 (v3)
# 自动生成于: $(date '+%Y-%m-%d %H:%M:%S')

global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
EOF

    # ============================================================
    # gNMIc (交换机) 配置
    # ============================================================
    if [[ ${#ONLINE_SWITCHES[@]} -gt 0 ]]; then
        cat >> "$output" << EOF
  # ============================================================
  # SONiC 交换机 (via gNMIc)
  # ============================================================
  - job_name: 'gnmic'
    static_configs:
      - targets: ['gnmic:$GNMIC_METRICS_PORT']
    metric_relabel_configs:
EOF

        # 为每个模块生成relabel规则
        for conf in "$MODULES_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue
            local module=$(basename "$conf" .conf)
            load_module_config "$module" || continue
            
            local map_file="$CACHE_DIR/all_${module}_map_new.txt"
            [[ ! -s "$map_file" ]] && continue
            
            # 检测OID前缀
            local first_oid=$(head -1 "$map_file" | cut -d'=' -f2)
            local prefix=$(echo "$first_oid" | grep -oE "0x[0-9a-f]{2}" | head -1)
            
            cat >> "$output" << EOF
      # ────────────────────────────────────────────────────────
      # $module (OID前缀: $prefix)
      # ────────────────────────────────────────────────────────
      - source_labels: [__name__]
        regex: 'sonic_COUNTERS_(oid_${prefix}[0-9a-f]+)_(.+)'
        replacement: '\${1}'
        target_label: ${module}_oid
      - source_labels: [__name__]
        regex: 'sonic_COUNTERS_(oid_${prefix}[0-9a-f]+)_(.+)'
        replacement: '${prometheus_prefix}_\${2}'
        target_label: __name__
      # OID到名称映射
EOF
            
            while IFS='=' read -r entry_name entry_oid; do
                local oid_clean=$(echo "$entry_oid" | sed 's/0x/oid_0x/')
                echo "      - source_labels: [${module}_oid]" >> "$output"
                echo "        regex: '${oid_clean}'" >> "$output"
                echo "        replacement: '${entry_name}'" >> "$output"
                echo "        target_label: $label_name" >> "$output"
            done < "$map_file"

            # 提取子标签
            if [[ -n "$extract_labels" ]]; then
                IFS=';' read -ra LABEL_RULES <<< "$extract_labels"
                for rule in "${LABEL_RULES[@]}"; do
                    local lbl_name=$(echo "$rule" | cut -d':' -f1)
                    local lbl_regex=$(echo "$rule" | cut -d':' -f2-3 | sed 's/:$//')
                    local lbl_replace=$(echo "$rule" | rev | cut -d':' -f1 | rev)
                    
                    echo "      - source_labels: [$label_name]" >> "$output"
                    echo "        regex: '${lbl_regex}'" >> "$output"
                    echo "        replacement: '${lbl_replace}'" >> "$output"
                    echo "        target_label: $lbl_name" >> "$output"
                done
            fi
            
            echo "" >> "$output"
        done

        # PFC提取
        cat >> "$output" << EOF
      # ────────────────────────────────────────────────────────
      # PFC 提取
      # ────────────────────────────────────────────────────────
      - source_labels: [__name__]
        regex: 'sonic_port_SAI_PORT_STAT_PFC_([0-7])_(RX|TX)_PKTS'
        replacement: '\${1}'
        target_label: pfc_priority
      - source_labels: [__name__]
        regex: 'sonic_port_SAI_PORT_STAT_PFC_([0-7])_(RX|TX)_PKTS'
        replacement: '\${2}'
        target_label: pfc_direction
      - source_labels: [__name__]
        regex: 'sonic_port_SAI_PORT_STAT_PFC_([0-7])_(RX|TX)_PKTS'
        replacement: 'sonic_port_PFC_PKTS'
        target_label: __name__

EOF

        # ACL类型映射
        load_acl_rule_mapping
        if [[ ${#ACL_RULE_MAPPING[@]} -gt 0 ]]; then
            cat >> "$output" << EOF
      # ────────────────────────────────────────────────────────
      # ACL 规则类型映射
      # ────────────────────────────────────────────────────────
EOF
            for rule_name in "${!ACL_RULE_MAPPING[@]}"; do
                local display_name=${ACL_RULE_MAPPING[$rule_name]}
                echo "      - source_labels: [acl_rule]" >> "$output"
                echo "        regex: '.+:${rule_name}'" >> "$output"
                echo "        replacement: '${display_name}'" >> "$output"
                echo "        target_label: acl_type" >> "$output"
            done
            echo "" >> "$output"
        fi
    fi

    # ============================================================
    # 服务器 RDMA 监控 (v3 新增)
    # ============================================================
    if [[ ${#ONLINE_SERVERS[@]} -gt 0 ]]; then
        cat >> "$output" << EOF
  # ============================================================
  # 服务器 RDMA 监控 (via node_exporter)
  # ============================================================
  - job_name: 'rdma_servers'
    scrape_interval: 1s
    static_configs:
      - targets:
EOF
        for name in "${ONLINE_SERVERS[@]}"; do
            local ip=${SERVER_IPS[$name]}
            local port=${SERVER_PORTS[$name]}
            echo "        - '${ip}:${port}'" >> "$output"
        done
        
        cat >> "$output" << EOF
        labels:
          group: 'rdma_servers'

EOF
    fi

    # ============================================================
    # Prometheus 自身监控
    # ============================================================
    cat >> "$output" << EOF
  # ============================================================
  # Prometheus 自身
  # ============================================================
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:$PROMETHEUS_PORT']
EOF

    log INFO "prometheus配置已生成"
}

# ============================================================
# 备份和缓存更新
# ============================================================

backup_configs() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_subdir="$BACKUP_DIR/$timestamp"
    
    mkdir -p "$backup_subdir"
    
    [[ -f "$GNMIC_DIR/gnmic.yaml" ]] && cp "$GNMIC_DIR/gnmic.yaml" "$backup_subdir/"
    [[ -f "$PROMETHEUS_DIR/prometheus.yml" ]] && cp "$PROMETHEUS_DIR/prometheus.yml" "$backup_subdir/"
    
    log DEBUG "配置已备份到: $backup_subdir"
    
    # 清理旧备份
    local backup_count=$(ls -d "$BACKUP_DIR"/*/ 2>/dev/null | wc -l)
    if [[ $backup_count -gt $BACKUP_RETENTION_COUNT ]]; then
        ls -dt "$BACKUP_DIR"/*/ | tail -n +$((BACKUP_RETENTION_COUNT + 1)) | xargs rm -rf
    fi
}

update_cache() {
    # 更新每个交换机的缓存
    for switch_name in "${ONLINE_SWITCHES[@]}"; do
        for file in "$CACHE_DIR/$switch_name"/*_new.txt; do
            [[ -f "$file" ]] && mv "$file" "${file/_new.txt/_old.txt}"
        done
    done
    
    # 更新合并的映射缓存
    for file in "$CACHE_DIR"/all_*_new.txt; do
        [[ -f "$file" ]] && mv "$file" "${file/_new.txt/_old.txt}"
    done
    
    # 保存在线交换机列表
    printf '%s\n' "${ONLINE_SWITCHES[@]}" > "$CACHE_DIR/switches_old.txt"
    
    # 保存在线服务器列表 (v3 新增)
    if [[ -f "$CACHE_DIR/servers_new.txt" ]]; then
        mv "$CACHE_DIR/servers_new.txt" "$CACHE_DIR/servers_old.txt"
    fi
}

# ============================================================
# 主函数
# ============================================================

show_help() {
    cat << EOF
SONiC Telemetry + Server RDMA 自动配置刷新脚本 v3

用法: $0 [选项]

选项:
  -h, --help      显示帮助信息
  -v, --verbose   详细输出模式
  -f, --force     强制更新（不提示确认）

特性:
  - 每台交换机独立订阅，避免OID冲突
  - 自动检测OID前缀
  - 支持多种Counter模块
  - 整合服务器 RDMA 监控 (v3 新增)

配置文件:
  config/switches.conf  - 交换机列表
  config/servers.conf   - 服务器列表 (v3 新增)
  config/settings.conf  - 全局设置
  config/modules/*.conf - 模块配置

EOF
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help; exit 0 ;;
            -v|--verbose) VERBOSE=true ;;
            -f|--force) FORCE=true ;;
            *) echo "未知选项: $1"; show_help; exit 1 ;;
        esac
        shift
    done
    
    mkdir -p "$CACHE_DIR" "$BACKUP_DIR" "$LOGS_DIR"
    
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║      SONiC Telemetry + Server RDMA 配置刷新工具 v3         ║${NC}"
    echo -e "${BLUE}║      (交换机独立订阅 + 服务器RDMA监控)                      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  日志: $LOG_FILE"
    
    load_settings
    load_switches
    load_servers
    
    check_connectivity
    collect_all_oids
    
    if compare_and_report || $FORCE; then
        if ! $FORCE; then
            echo ""
            read -p "是否更新配置? (y/n): " confirm
            [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { echo "已取消"; exit 0; }
        fi
        
        print_header "4/4 生成配置"
        
        backup_configs
        generate_gnmic_config
        generate_prometheus_config
        update_cache
        
        echo ""
        echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  配置更新完成！${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "  请运行以下命令应用配置:"
        echo ""
        echo -e "    ${CYAN}cd $BASE_DIR && docker compose restart gnmic prometheus${NC}"
        echo ""
    else
        echo ""
        echo -e "${GREEN}配置无需更新${NC}"
    fi
}

main "$@"
