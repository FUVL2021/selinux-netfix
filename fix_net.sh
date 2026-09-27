#!/system/bin/sh
# ============================================================
# fix_net.sh —— SELinux 网络缓存一键修复
# ============================================================
# 修复被 exploit（CVE-2026-43499 / GhostLock 等）污染后的
# SELinux 网络缓存。
#
# 症状：permissive 下联网正常，enforcing 下断网 / App 闪退。
# dmesg 里能看到：
#   tcontext=u:object_r:unlabeled:s0 tclass=packet
#
# 适用范围：所有由 CVE-2026-43499 导致无法联网的设备，
#           不限机型/厂商，只要内核是 GKI 即可。
#           本脚本不含任何设备/内核偏移量，跨机型通用。
#
# 需要 root（或具备相应 SELinux 权限的域）执行。
#
# 作者：酷安 FUVL2210
# 许可证：MIT
#
# 用法：sh fix_net.sh
# ============================================================

set -u

echo "========================================"
echo " SELinux 网络缓存修复 (fix_net.sh)"
echo "========================================"

# ---- 记录原始 enforce 值 ----
ORIG=$(cat /sys/fs/selinux/enforce 2>/dev/null)
if [ -z "$ORIG" ]; then
    echo "[-] 无法读取 /sys/fs/selinux/enforce（需要 root）"
    exit 1
fi
echo "[*] 原始 enforce = $ORIG"

# ---- 步骤 1: 临时切 permissive ----
if [ "$ORIG" = "1" ]; then
    echo "[*] 临时切 permissive ..."
    echo 0 > /sys/fs/selinux/enforce || {
        echo "[-] 切换失败，请确认有 root 权限"
        exit 1
    }
fi

# ---- 步骤 2: 重载策略（核心）----
# 关键：必须一次性原子写入。cat 会分 4096 字节多次 write()，
# 内核判为不完整 → EINVAL ("xwrite: Invalid argument")。
# 用 dd + 足够大的 bs（4M > policy 约 1.7MB）保证单次写入。
echo "[*] 重载 SELinux 策略（触发 sel_netif_flush）..."
if dd if=/sys/fs/selinux/policy of=/sys/fs/selinux/load bs=4M 2>/dev/null; then
    echo "[+] 策略重载成功"
else
    echo "[-] 策略重载失败（可能是权限不足，或非原子写入）"
    [ "$ORIG" = "1" ] && echo 1 > /sys/fs/selinux/enforce
    exit 1
fi

# ---- 步骤 3: 重建 lo ----
# 清空只是第一步，lo 的条目需要被重新创建，否则依旧 unlabeled。
echo "[*] 重建 lo ..."
ip link set lo down 2>/dev/null
ip link set lo up   2>/dev/null
ip addr add 127.0.0.1/8 dev lo 2>/dev/null
echo "[+] lo 已重建"

# ---- 步骤 4: 重建 wlan0（可选）----
echo "[*] 重建 wlan0（可选）..."
ip link set wlan0 down 2>/dev/null
sleep 1
ip link set wlan0 up   2>/dev/null
echo "[+] wlan0 已重建"

# ---- 步骤 5: 恢复 enforcing ----
if [ "$ORIG" = "1" ]; then
    echo "[*] 恢复 enforcing ..."
    echo 1 > /sys/fs/selinux/enforce && echo "[+] 已恢复 enforcing"
fi

echo ""
echo "========================================"
echo "[+] 修复流程完成"
echo "    验证：dmesg | grep 'unlabeled.*packet'"
echo "    输出为空即表示缓存已恢复正常。"
echo "========================================"