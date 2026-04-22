#define SEC(name) __attribute__((section(name), used))

static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    int (*type)[1];
    int *key;
    int *value;
    int (*max_entries)[1];
} my_map SEC(".maps");

SEC("test")
int bitwise_map(void *ctx) {
    int key = 0;
    int *val = (int *)bpf_map_lookup_elem(&my_map, &key);
    if (!val)
        return 0;

    /* Bitwise AND on the map value */
    return *val & 0xFF;
}

char LICENSE[] SEC("license") = "GPL";
