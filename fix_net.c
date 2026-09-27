/*
 * fix_net.c —— SELinux 网络缓存修复工具
 * ============================================
 *
 * 背景
 * ----
 * 内核漏洞利用（如 CVE-2026-43499 / GhostLock 这类 slide 攻击）在做
 * 任意读写时，会连带破坏内核 slab cache，其中包括 SELinux 的三张
 * 网络缓存哈希表：
 *
 *     sel_netif    网络接口 → SELinux 标签
 *     sel_netnode  IP 节点  → SELinux 标签
 *     sel_netport  端口     → SELinux 标签
 *
 * 缓存被污染后，包会被标记为
 *     tcontext=u:object_r:unlabeled:s0 tclass=packet
 * 于是：permissive 下网络正常，enforcing 下断网 / App 因 lo socket
 * 被拒而闪退。
 *
 * 适用范围
 * --------
 * **所有由 CVE-2026-43499 导致无法联网的设备，不限机型/厂商**，
 * 只要内核是 GKI（5.4 / 5.10 / 5.15 / 6.1+）。
 * 本工具不依赖任何内核偏移量，跨设备直接可用。
 *
 * 修复
 * ----
 * 1) 重新加载 SELinux 策略（写 /sys/fs/selinux/load）会触发内核调用
 *      sel_netif_flush() / sel_netnode_flush() / sel_netport_flush()
 *    把被污染的三张缓存表清空。
 * 2) 清空后需要「重建」接口条目：对 lo 做 down/up + 重新分配 IP，
 *    触发接口重新注册与标签重分配。
 *
 * 注意
 * ----
 * · /sys/fs/selinux/load 要求策略**一次性原子写入**（单次 write()）。
 *   分段写（cat 的 4096 字节小写）会被内核判为不完整 → EINVAL。
 *   因此这里一次性 malloc 整个策略 + 单次 write()。
 * · 需要 root 或具备相应 SELinux 权限的域。
 *
 * 编译
 * ----
 *   aarch64-linux-gnu-gcc -O2 -static -o fix_net fix_net.c
 *
 * 用法
 * ----
 *   ./fix_net           # 修复（自动保存并恢复 enforce 值）
 *   ./fix_net --check   # 只检查当前状态，不做任何修改
 *
 * 作者：酷安 FUVL2210
 * 许可证：MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#define POLICY_PATH "/sys/fs/selinux/policy"
#define LOAD_PATH   "/sys/fs/selinux/load"
#define ENFORCE_PATH "/sys/fs/selinux/enforce"

/* ---- 小工具：读写 /sys 下的单行整数值 ---- */
static int read_int_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return atoi(buf);
}

static int write_int_file(const char *path, int val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "%d", val);
    ssize_t n = write(fd, buf, len);
    close(fd);
    return (n == len) ? 0 : -1;
}

/* ---- 检查当前 SELinux / 网络缓存状态 ---- */
static void check_state(void)
{
    printf("[*] SELinux 状态检查\n");
    int enforcing = read_int_file(ENFORCE_PATH);
    if (enforcing < 0)
        printf("    enforce : (读取失败, errno=%d)\n", errno);
    else
        printf("    enforce : %d (%s)\n", enforcing,
               enforcing ? "enforcing" : "permissive");

    struct stat st;
    if (stat(POLICY_PATH, &st) == 0)
        printf("    policy  : %s, %lld bytes\n", POLICY_PATH,
               (long long)st.st_size);
    else
        printf("    policy  : (stat 失败, errno=%d)\n", errno);

    printf("\n[*] 提示：若 enforce=1 时出现 AVC 拒绝\n");
    printf("    tcontext=u:object_r:unlabeled:s0 tclass=packet\n");
    printf("    即为本节所述「网络缓存被污染」问题。\n");
}

/*
 * 核心：一次性原子重载 SELinux 策略。
 * 返回 0 成功，非 0 失败。
 */
static int reload_policy(void)
{
    struct stat st;
    if (stat(POLICY_PATH, &st) != 0) {
        fprintf(stderr, "[-] stat(%s) 失败: %s\n", POLICY_PATH, strerror(errno));
        return 1;
    }
    size_t sz = (size_t)st.st_size;
    if (sz == 0) {
        fprintf(stderr, "[-] 策略文件为空\n");
        return 1;
    }
    printf("[*] policy size: %zu bytes\n", sz);

    /* 用 posix_memalign 对齐，读大文件更稳 */
    char *buf = NULL;
    if (posix_memalign((void **)&buf, 4096, sz) != 0 || !buf) {
        fprintf(stderr, "[-] malloc 失败\n");
        return 1;
    }

    /* 1) 一次性读出整个策略 */
    int fd = open(POLICY_PATH, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[-] open(policy) 失败: %s\n", strerror(errno));
        free(buf);
        return 1;
    }
    size_t got = 0;
    while (got < sz) {
        ssize_t n = read(fd, buf + got, sz - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[-] read(policy) 失败: %s\n", strerror(errno));
            close(fd);
            free(buf);
            return 1;
        }
        if (n == 0) break;
        got += (size_t)n;
    }
    close(fd);
    if (got != sz) {
        fprintf(stderr, "[-] 读取不完整: %zu/%zu\n", got, sz);
        free(buf);
        return 1;
    }

    /* 2) 一次性原子写入 load —— 关键：必须是单次 write() */
    fd = open(LOAD_PATH, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[-] open(load) 失败: %s (需要 root 权限)\n",
                strerror(errno));
        free(buf);
        return 1;
    }
    ssize_t n = write(fd, buf, sz);
    int saved = errno;
    close(fd);
    free(buf);

    printf("[*] write(load) 返回: %zd (errno=%d)\n", n, saved);
    if (n == (ssize_t)sz) {
        printf("[+] 策略重载成功 —— sel_netif/netnode/netport 缓存已清空\n");
        return 0;
    }
    fprintf(stderr, "[-] 策略重载失败: %s\n",
            saved ? strerror(saved) : "写入长度不足");
    return 1;
}

/* 用 system() 跑 ip 命令；失败不致命（部分环境无 ip 命令） */
static void try_cmd(const char *desc, const char *cmd)
{
    printf("[*] %s\n", desc);
    int rc = system(cmd);
    if (rc != 0)
        printf("    (退出码 %d，可能无 ip 命令或权限不足，可忽略)\n", rc);
}

int main(int argc, char **argv)
{
    printf("========================================\n");
    printf(" SELinux 网络缓存修复工具 (fix_net)\n");
    printf("========================================\n\n");

    if (argc > 1 && strcmp(argv[1], "--check") == 0) {
        check_state();
        return 0;
    }

    /* 记录原始 enforce 值，修复后恢复 */
    int orig_enforce = read_int_file(ENFORCE_PATH);
    printf("[*] 原始 enforce = %d\n", orig_enforce);

    /* ---- 步骤 1: 临时切 permissive，避免修复过程被拦 ---- */
    if (orig_enforce == 1) {
        printf("[*] 临时切换为 permissive ...\n");
        if (write_int_file(ENFORCE_PATH, 0) != 0)
            fprintf(stderr, "[!] 切换 permissive 失败: %s（继续尝试）\n",
                    strerror(errno));
        else
            printf("[+] 已切 permissive\n");
    }
    printf("\n");

    /* ---- 步骤 2: 重载策略（核心）---- */
    printf("---- 步骤 2: 重载 SELinux 策略 ----\n");
    if (reload_policy() != 0) {
        fprintf(stderr, "\n[!] 策略重载失败，后续重建接口意义有限。\n");
        if (orig_enforce == 1) write_int_file(ENFORCE_PATH, 1);
        return 1;
    }
    printf("\n");

    /* ---- 步骤 3: 重建 lo ---- */
    printf("---- 步骤 3: 重建 lo 接口 ----\n");
    try_cmd("lo down", "ip link set lo down 2>/dev/null");
    try_cmd("lo up",   "ip link set lo up 2>/dev/null");
    try_cmd("lo 分配 127.0.0.1/8",
            "ip addr add 127.0.0.1/8 dev lo 2>/dev/null");
    printf("\n");

    /* ---- 步骤 4: 重建 wlan0（可选）---- */
    printf("---- 步骤 4: 重建 wlan0（可选）----\n");
    try_cmd("wlan0 down/up",
            "ip link set wlan0 down 2>/dev/null; "
            "sleep 1; ip link set wlan0 up 2>/dev/null");
    printf("\n");

    /* ---- 步骤 5: 恢复 enforce ---- */
    if (orig_enforce == 1) {
        printf("---- 步骤 5: 恢复 enforcing ----\n");
        if (write_int_file(ENFORCE_PATH, 1) == 0)
            printf("[+] 已恢复 enforcing\n");
        else
            fprintf(stderr, "[!] 恢复 enforcing 失败: %s\n", strerror(errno));
    } else {
        printf("[*] 原始非 enforcing，保持当前状态\n");
    }

    printf("\n========================================\n");
    printf("[+] 修复流程完成\n");
    printf("    验证：dmesg | grep 'unlabeled.*packet'\n");
    printf("    输出为空即表示缓存已恢复正常。\n");
    printf("========================================\n");
    return 0;
}