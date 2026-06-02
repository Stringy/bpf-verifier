#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("test")
int ringbuf_wrong_return(void *ctx) {
    int *event = (int *)bpf_ringbuf_reserve(&events, sizeof(int), 0);
    if (!event)
        return 1;
    *event = 42;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
