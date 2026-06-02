#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} my_map SEC(".maps");

SEC("test")
int nested_branch(void *ctx) {
    int key = 0;
    int *val = (int *)bpf_map_lookup_elem(&my_map, &key);
    if (!val)
        return -1;

    if (*val > 100)
        return *val;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
