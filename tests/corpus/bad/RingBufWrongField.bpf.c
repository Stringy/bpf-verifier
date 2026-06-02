#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

struct event {
    unsigned int type;
    unsigned int flags;
};

SEC("test")
int ringbuf_wrong_field(void *ctx) {
    struct event *e = (struct event *)bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 1;
    e->type = 7;
    e->flags = 0xAA;   /* spec expects 0xFF but we wrote 0xAA */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
