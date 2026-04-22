#define SEC(name) __attribute__((section(name), used))

static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    int (*type)[1];
    int *key;
    int *value;
    int (*max_entries)[1];
} my_map SEC(".maps");

SEC("test")
int map_default_value(void *ctx) {
    int key = 0;
    int *val = (int *)bpf_map_lookup_elem(&my_map, &key);

    /* Common BPF pattern: use value if found, default otherwise */
    int result = val ? *val : 42;
    return result;
}

char LICENSE[] SEC("license") = "GPL";
