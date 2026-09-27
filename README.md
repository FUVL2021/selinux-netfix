# 局域网联网修复工具（SELinux 网络缓存修复）

> 修复被内核漏洞利用（exploit）污染后的 SELinux 网络缓存 —— 症状是 **permissive 下联网正常、enforcing 下断网 / App 闪退**。

**作者：酷安 FUVL2210**

---

## 一、这是什么问题？

Android 的 SELinux 会对**网络通信**做强制访问控制。内核需要知道：**一个网络包属于哪个 SELinux 上下文？**

答案是一组内核哈希表缓存：

| 内核结构 | 作用 |
|----------|------|
| `sel_netif`   | 缓存网络接口（如 `wlan0`、`lo`）→ SELinux 标签的映射 |
| `sel_netnode` | 缓存 IP 节点 → 标签 |
| `sel_netport` | 缓存端口 → 标签 |

当数据包经过网络栈时，内核查这些表得到 `scontext` / `tcontext`。如果查不到、或缓存被破坏，包就会被标记为：

```
tcontext=u:object_r:unlabeled:s0 tclass=packet
```

然后在 enforcing 模式下被 SELinux 拒绝。

### 成因：exploit 污染了缓存

像 GhostLock（CVE-2026-43499）这类 **slide 攻击**，会通过 `FUTEX + tracepoint` 在内核里做任意读写。它的目标虽然是 `credential`，但内存读写过程会**连带破坏内核 slab cache**，包括上面那三张 SELinux 网络缓存表。

被污染后：

1. `sel_netif` 等哈希表里的条目变成损坏 / 错误值
2. 网络接口查不到正确标签 → 全部 fallback 到 `unlabeled`
3. permissive 下网络正常（不拦截），**enforcing 下断网**（全被拒）
4. 依赖 `lo` 本地 socket 通信的应用，一发起连接就被 AVC 拒绝 → **闪退**

### 为什么 `lo` 特别顽固

`wlan0` 等物理接口在 down/up 时会重新注册，可能触发缓存重建。但 `lo`（回环）通常一直存在、不会被重新初始化，所以它的错误缓存条目**不会自己消失** —— 这也是为什么「单独重建 `lo`」往往不够。

---

## 二、修复原理

### 核心：重载 SELinux 策略

内核函数 **`sel_netif_flush()`** 是钥匙。当新的 SELinux 策略被加载（写入 `/sys/fs/selinux/load`）时，内核会调用一系列 flush 函数，其中就包括：

```
sel_netif_flush()   → 清空 sel_netif  哈希表
sel_netnode_flush() → 清空 sel_netnode 哈希表
sel_netport_flush() → 清空 sel_netport 哈希表
```

**这正好把被污染的网络缓存全部清空。** 清空之后，缓存是空的（不再是「错误条目」）。当下一个包经过时，内核会**重新查询并重新填充**正确条目。

### 还要重建 `lo`

重载策略只做了「清空」。清空后缓存需要在接口被访问时**重新创建条目**。

对 `lo` 来说，要触发重新创建：

```bash
ip link set lo down
ip link set lo up
ip addr add 127.0.0.1/8 dev lo
```

- `down/up` 触发接口重新注册
- 分配 IP 触发 `sel_netif` 为该接口重新分配标签条目
- 这样 `lo` 的缓存才从「空」变成「正确」

**只重载不重建** = 缓存被清空了，但 `lo` 的条目一直没被重新创建 → 依然 `unlabeled`。

### 为什么必须用 `dd` 而不是 `cat`

`/sys/fs/selinux/load` 要求**策略作为单次 `write()` 系统调用原子写入**：

- `cat policy > load` 会分多次 `write()`（每次约 4096 字节）
- 内核检测到不完整写入 → 返回 `EINVAL` → 报错 `xwrite: Invalid argument`

`dd` 配合足够大的 `bs`（如 `bs=4M`，大于 policy 文件约 1.7MB）可以一次读完、一次写完，满足原子性要求。

---

## 三、用法

### 1. 手工执行（shell 脚本）

```bash
# 1) 临时切 permissive —— 修复过程中避免被 SELinux 拦截
echo 0 > /sys/fs/selinux/enforce

# 2) 重载策略（关键）—— 触发 sel_netif_flush() 清空污染缓存
#    注意：必须一次性原子写入，cat 分段写会失败
dd if=/sys/fs/selinux/policy of=/sys/fs/selinux/load bs=4M 2>/dev/null

# 3) 重建 lo —— 让 lo 重新注册 + 分配地址，触发缓存重建
ip link set lo down
ip link set lo up
ip addr add 127.0.0.1/8 dev lo 2>/dev/null

# 4) 重建 wlan0（可选）—— 物理接口也可能缓存了错误标签
ip link set wlan0 down && sleep 1 && ip link set wlan0 up

# 5) 恢复 enforcing —— 此时缓存已正常，不会再 unlabeled 拒绝
echo 1 > /sys/fs/selinux/enforce
```

### 2. C 版本（本仓库 `fix_net.c`）

C 版本把「策略重载」这一步做实了，并带有完整的错误处理与状态检查：

```bash
# 交叉编译（arm64）
aarch64-linux-gnu-gcc -O2 -static -o fix_net fix_net.c

# 推送到设备并执行（需要 root 或 shell 域）
adb push fix_net /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/fix_net && /data/local/tmp/fix_net"
```

---

## 四、验证修复是否成功

```bash
# 修复后清空 dmesg，然后触发网络活动
dmesg -c > /dev/null
# 打开依赖网络的 App，或用 curl / ping

# 检查是否还有 unlabeled packet 拒绝（应该为空）
dmesg | grep "unlabeled.*packet" | tail -5
```

如果输出为空，说明缓存已修复。

另一个更直接的判据：把 SELinux 切回 enforcing，看 `lo` 的本地 socket 是否还报 AVC：

```bash
cat /sys/fs/selinux/enforce        # 应为 1
dmesg | grep -i "avc.*lo" | tail   # 应为空
```

---

## 五、通用性

此修复方法适用于：

- **所有 GKI 内核**（5.4 / 5.10 / 5.15 / 6.1+）
- 任何**污染了内核 SELinux 网络缓存的提权 / 内存读写类 exploit**（不只是 GhostLock）
- 只要现象是：**permissive 正常、enforcing 断网、AVC 出现 `unlabeled` + `tclass=packet`**

修复脚本**跨设备可用**，无需针对特定内核偏移量 —— 因为它不碰任何 exploit 细节，只利用「策略重载 → flush」这一内核既有行为。

---

## 六、小结

| 问题 | 成因 | 修复动作 | 原理 |
|------|------|----------|------|
| enforcing 下断网 | `sel_netif` 等缓存被 exploit 污染 | 重载策略 | 触发 `sel_netif_flush()` 清空污染缓存 |
| `lo` 持续 unlabeled | 缓存清空后 `lo` 条目未重建 | `lo` down/up + 分配 IP | 触发接口重新注册和标签重分配 |
| `cat` 报 EINVAL | 策略需原子写入 | 用 `dd` 大块写入 | 满足单次 `write()` 要求 |
| 应用闪退 | `lo` 本地 socket 被拒 | 上述全套 | 恢复 `lo` 的正确 SELinux 上下文 |

---

## 七、目录结构

```
.
├── README.md      # 本说明
├── fix_net.c      # C 版修复工具（策略重载 + 说明输出）
├── fix_net.sh     # shell 版一键修复脚本
└── LICENSE        # MIT
```

---

## 八、免责声明

本工具仅用于**你自己拥有的设备**的安全研究与故障恢复。

它做的事情是：把设备**当前**的 SELinux 策略重新加载一遍，以刷新内核网络缓存。**不修改策略内容、不关闭 SELinux、不改动任何分区**。

请勿用于任何非授权设备。

---

## 九、作者

- **酷安：FUVL2210**
- GitHub：`FUVL2210`

如有问题或改进建议，欢迎提 Issue / PR。