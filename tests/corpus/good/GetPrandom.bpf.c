#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int get_prandom(void *ctx) {
    unsigned int r = bpf_get_prandom_u32();
    return (int)(r & 0xFF);
}

char LICENSE[] SEC("license") = "GPL";
