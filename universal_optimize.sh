#!/bin/sh
# universal_optimize_alpine.sh
# 通用安全网络优化，已适配 Alpine Linux (OpenRC)
# - 幂等可重复执行
# - 失败默认忽略（不锁机、不卡网）
# - 不修改应用/防火墙/代理配置
set -eu

ACTION="${1:-apply}"
# --- Alpine (OpenRC) paths ---
SYSCTL_FILE="/etc/sysctl.d/99-universal-net.conf"
LIMITS_FILE="/etc/security/limits.d/99-universal.conf"
OFFLOAD_SERVICE="/etc/init.d/univ-offload"
IRQPIN_SERVICE="/etc/init.d/univ-irqpin"
HEALTH_SERVICE="/etc/init.d/univ-health"
CONF_D_FILE="/etc/conf.d/universal-optimize"

#------------- helpers -------------
ok()   { printf "\033[32m%s\033[0m\n" "$*"; }
warn() { printf "\033[33m%s\033[0m\n" "$*"; }
err()  { printf "\033[31m%s\033[0m\n" "$*"; }

detect_iface() {
  # IFACE 可由环境变量覆盖：IFACE=eth0 sh universal_optimize_alpine.sh apply
  if [ -n "${IFACE:-}" ] && [ -e "/sys/class/net/${IFACE}" ]; then
    echo "$IFACE"; return
  fi
  # 1) 优先路由探测
  dev="$(ip -o route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  if [ -n "$dev" ] && [ -e "/sys/class/net/${dev}" ]; then
    echo "$dev"; return
  fi
  # 2) 第一个非 lo 的 UP 接口
  dev="$(ip -o link show up 2>/dev/null | awk -F': ' '$2!="lo"{print $2; exit}' || true)"
  if [ -n "$dev" ] && [ -e "/sys/class/net/${dev}" ]; then
    echo "$dev"; return
  fi
  # 3) 兜底：第一个非 lo 接口
  dev="$(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo"{print $2; exit}' || true)"
  [ -n "$dev" ] && echo "$dev"
}

pkg_install() {
  command -v ethtool >/dev/null 2>&1 && return 0
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache ethtool >/dev/null 2>&1 || true
  else
    warn "非 Alpine 系统且 ethtool 未安装，请手动安装"
  fi
}

runtime_sysctl_safe() {
  # 按键值对运行态注入，忽略不存在的键，避免报错
  # 使用 POSIX read 和 case 语句替代 bashisms
  while IFS='=' read -r k v_comment; do
    k=$(echo "$k" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    v=$(echo "$v_comment" | sed 's/#.*//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$k" in
      ""|\#*) continue ;;
    esac
    sysctl -w "$k=$v" >/dev/null 2>&1 || true
  done <<'KV'
net.core.rmem_default=4194304
net.core.wmem_default=4194304
net.core.optmem_max=8388608
net.core.netdev_max_backlog=50000
net.core.somaxconn=16384
net.ipv4.ip_local_port_range=10240 65535
net.ipv4.udp_mem=8192 16384 32768
net.ipv4.udp_rmem_min=131072
net.ipv4.udp_wmem_min=131072
KV
}

apply_sysctl() {
  cat >"$SYSCTL_FILE" <<'CONF'
# === universal-optimize: safe network tuning ===
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.optmem_max   = 8388608
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 16384
net.ipv4.ip_local_port_range = 10240 65535
# UDP pages triple ≈ 32MB / 64MB / 128MB (4K page)
net.ipv4.udp_mem      = 8192 16384 32768
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
CONF
  runtime_sysctl_safe
  # Alpine 的 sysctl 默认会加载 /etc/sysctl.d
  /sbin/sysctl -p >/dev/null 2>&1 || true
  ok "[universal-optimize] sysctl 已应用并持久化：$SYSCTL_FILE"
}

apply_limits() {
  mkdir -p "$(dirname "$LIMITS_FILE")"
  cat >"$LIMITS_FILE" <<'LIM'
* soft nofile 1048576
* hard nofile 1048576
* soft nproc  unlimited
* hard nproc  unlimited
LIM
  ok "[universal-optimize] ulimit 默认提升（新会话/服务生效）"
}

apply_conf_d() {
  mkdir -p "$(dirname "$CONF_D_FILE")"
  cat >"$CONF_D_FILE" <<EOF
# universal-optimize 服务的配置文件
# 由脚本自动生成
IFACE="${1}"
SYSCTL_FILE="${SYSCTL_FILE}"
EOF
}

apply_offload_openrc() {
  local iface="$1"
  cat >"$OFFLOAD_SERVICE" <<'UNIT'
#!/sbin/openrc-run
description="Universal: disable NIC offloads"
supervisor="supervise-daemon"

depend() {
    need net
    after net
}

start() {
    . /etc/conf.d/universal-optimize 2>/dev/null || true
    IFACE=${IFACE:-$(ip -o route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)}
    
    if [ -z "$IFACE" ] || ! [ -d "/sys/class/net/$IFACE" ]; then
        eerror "Offload: 无法找到网卡 $IFACE"
        return 1
    fi

    ET=$(command -v ethtool || echo /usr/sbin/ethtool)
    if ! [ -x "$ET" ]; then
        ewarn "Offload: ethtool 不存在，跳过"
        return 0
    fi
    
    einfo "正在为网卡 $IFACE 关闭 offload 特性..."
    # 等待链路 UP (最多 8s)
    i=0
    while [ $i -lt 16 ]; do
        if ip link show "$IFACE" 2>/dev/null | grep -q "state UP"; then
            break
        fi
        sleep 0.5
        i=$((i + 1))
    done

    $ET -K "$IFACE" gro off gso off tso off lro off scatter-gather off rx-gro-hw off rx-udp-gro-forwarding off >/dev/null 2>&1 || true
    return 0
}

stop() {
    return 0 # 不需要操作
}
UNIT
  chmod 755 "$OFFLOAD_SERVICE"
  rc-update add univ-offload default >/dev/null 2>&1
  rc-service univ-offload restart >/dev/null 2>&1
  ok "[universal-optimize] OpenRC 持久化 offload 关闭: univ-offload"

  if command -v ethtool >/dev/null 2>&1 || [ -x /usr/sbin/ethtool ]; then
    (ethtool -K "$iface" gro off gso off tso off lro off scatter-gather off rx-gro-hw off rx-udp-gro-forwarding off >/dev/null 2>&1 || true)
    ok "[universal-optimize] 已对 $iface 进行一次性 offload 关闭尝试"
  fi
}

apply_irqpin_openrc() {
  cat >"$IRQPIN_SERVICE" <<'UNIT'
#!/sbin/openrc-run
description="Universal: pin NIC IRQs to CPU0 (safe)"
supervisor="supervise-daemon"

depend() {
    need net
    after net
}

start() {
    . /etc/conf.d/universal-optimize 2>/dev/null || true
    IFACE=${IFACE:-$(ip -o route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)}

    if [ -z "$IFACE" ] || ! [ -d "/sys/class/net/$IFACE" ]; then
        eerror "IRQ: 无法找到网卡 $IFACE"
        return 1
    fi

    einfo "尝试为 $IFACE 绑定中断到 CPU0..."
    main_irq=$(cat "/sys/class/net/$IFACE/device/irq" 2>/dev/null || true)
    if [ -n "$main_irq" ] && [ -w "/proc/irq/$main_irq/smp_affinity" ]; then
        echo 1 > "/proc/irq/$main_irq/smp_affinity" 2>/dev/null && einfo "IRQ: 主中断 $main_irq -> CPU0"
    else
        einfo "IRQ: 未发现主中断（虚拟网卡常见，跳过）"
    fi

    for f in /sys/class/net/$IFACE/device/msi_irqs/*; do
        [ -f "$f" ] || continue
        irq=$(basename "$f")
        echo 1 > "/proc/irq/$irq/smp_affinity" 2>/dev/null && einfo "IRQ: MSI 中断 $irq -> CPU0"
    done
    return 0
}

stop() {
    return 0
}
UNIT
  chmod 755 "$IRQPIN_SERVICE"
  rc-update add univ-irqpin default >/dev/null 2>&1
  rc-service univ-irqpin restart >/dev/null 2>&1
  ok "[universal-optimize] IRQ 绑定服务已配置（缺 IRQ 时自动跳过）"
}

apply_health_openrc() {
  cat >"$HEALTH_SERVICE" <<'UNIT'
#!/sbin/openrc-run
description="Universal Optimize: boot health report"
supervisor="supervise-daemon"

depend() {
    after net univ-offload univ-irqpin
}

start() {
    einfo "开始生成网络优化自检报告..."
    . /etc/conf.d/universal-optimize 2>/dev/null || true
    IF="${IFACE:-$(ip -o route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
    ET=$(command -v ethtool || echo /usr/sbin/ethtool)

    echo "=== 自检报告 ($(date "+%F %T")) ==="
    rc-service univ-offload status 2>/dev/null | grep -q "started" && echo "offload: active" || echo "offload: inactive"
    rc-service univ-irqpin status 2>/dev/null | grep -q "started" && echo "irqpin : active" || echo "irqpin : inactive/ignored"
    [ -n "${SYSCTL_FILE:-}" ] && [ -f "${SYSCTL_FILE:-}" ] && echo "sysctl : ${SYSCTL_FILE}" || echo "sysctl : missing"
    
    if [ -x "$ET" ] && [ -n "$IF" ]; then
      $ET -k "$IF" 2>/dev/null | grep -E -i "gro|gso|tso|lro|scatter-gather" | sed -n "1,40p" || true
    fi
    sysctl -n net.core.rmem_default net.core.wmem_default net.core.optmem_max \
             net.core.netdev_max_backlog net.core.somaxconn net.ipv4.udp_mem \
             net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min 2>/dev/null | nl -ba || true
    return 0
}
UNIT
  chmod 755 "$HEALTH_SERVICE"
  rc-update add univ-health default >/dev/null 2>&1
}

status_report() {
  local iface="$1"
  echo "=== 状态报告 ($(date '+%F %T')) ==="
  echo "- 目标网卡：$iface"
  echo "- sysctl 文件：$SYSCTL_FILE"
  sysctl -n net.core.rmem_default net.core.wmem_default net.core.optmem_max \
           net.core.netdev_max_backlog net.core.somaxconn net.ipv4.udp_mem \
           net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min 2>/dev/null | nl -ba || true
  echo
  ET=$(command -v ethtool || echo /usr/sbin/ethtool)
  if [ -x "$ET" ]; then
    $ET -k "$iface" 2>/dev/null | grep -E -i 'gro|gso|tso|lro|scatter-gather' | sed -n '1,60p' || true
  else
    warn "ethtool 不存在，无法显示 offload 细节"
  fi
  echo
  echo "服务自启动状态 (rc-update show -v):"
  rc-update show -v | grep -E "univ-offload|univ-irqpin" || echo "  (未找到相关服务)"
  echo
  echo "服务当前运行状态 (rc-service --status):"
  rc-service univ-offload status 2>/dev/null
  rc-service univ-irqpin status 2>/dev/null
}

repair_missing() {
  [ -f "$SYSCTL_FILE" ] || apply_sysctl
  [ -f "$LIMITS_FILE" ] || apply_limits
  [ -f "$CONF_D_FILE" ] || apply_conf_d "$IFACE"
  [ -f "$OFFLOAD_SERVICE" ] || apply_offload_openrc "$IFACE"
  [ -f "$IRQPIN_SERVICE"  ] || apply_irqpin_openrc "$IFACE"
  [ -f "$HEALTH_SERVICE"  ] || apply_health_openrc
  ok "✅ 缺失项已自动补齐"
}

#------------- main -------------
IFACE="$(detect_iface || true)"
if [ -z "$IFACE" ]; then
  err "[universal-optimize] 无法自动探测网卡，请用 IFACE=xxx 再试"
  exit 1
fi

case "$ACTION" in
  apply)
    pkg_install
    apply_sysctl
    apply_limits
    apply_conf_d "$IFACE"
    apply_offload_openrc "$IFACE"
    apply_irqpin_openrc "$IFACE"
    apply_health_openrc
    status_report "$IFACE"
    ;;
  status)
    status_report "$IFACE"
    ;;
  repair)
    pkg_install
    repair_missing
    status_report "$IFACE"
    ;;
  *)
    echo "用法：sh $0 [apply|status|repair]"
    echo "示例：IFACE=eth0 sh $0 apply    # 手动指定网卡"
    exit 1
    ;;
esac
