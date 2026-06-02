#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} my_map SEC(".maps");

SEC("test")
int map_update(void *ctx) {
    int key = 0;
    int val = 42;

    /* Update the map with a new value */
    long err = bpf_map_update_elem(&my_map, &key, &val, 0);
    if (err)
        return -1;

    /* Read it back */
    int *result = (int *)bpf_map_lookup_elem(&my_map, &key);
    if (!result)
        return -2;

    return *result;
}

char LICENSE[] SEC("license") = "GPL";
