#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} my_map SEC(".maps");

SEC("test")
int map_delete(void *ctx) {
    int key = 0;

    /* Check if key exists */
    int *val = (int *)bpf_map_lookup_elem(&my_map, &key);
    if (!val)
        return 0;

    int saved = *val;

    /* Delete the key */
    long err = bpf_map_delete_elem(&my_map, &key);
    if (err)
        return -1;

    return saved;
}

char LICENSE[] SEC("license") = "GPL";
