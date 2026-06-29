// simple_filter.c — A minimal BPF socket filter for testing the converter.
//
// This programme:
// 1. Declares a hash map
// 2. Looks up a key in the map (returns nullable pointer)
// 3. Null-checks the result
// 4. Reads the value if non-null
// 5. Returns 1 (pass) or 0 (drop)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");

SEC("socket_filter")
int my_filter(struct __sk_buff *ctx) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&my_map, &key);
    if (val) {
        return *val > 100 ? 1 : 0;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
