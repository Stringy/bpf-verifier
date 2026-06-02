#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} my_map SEC(".maps");

SEC("test")
int map_callee_saved(void *ctx) {
    int key1 = 0;
    int *val1 = (int *)bpf_map_lookup_elem(&my_map, &key1);
    if (!val1)
        return -1;

    /* Save the checked pointer value before the second call.
       The compiler will use a callee-saved register for this. */
    int saved = *val1;

    int key2 = 1;
    int *val2 = (int *)bpf_map_lookup_elem(&my_map, &key2);
    if (!val2)
        return saved;

    return saved + *val2;
}

char LICENSE[] SEC("license") = "GPL";
