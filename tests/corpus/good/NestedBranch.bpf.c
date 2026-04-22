#define SEC(name) __attribute__((section(name), used))

static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    int (*type)[1];
    int *key;
    int *value;
    int (*max_entries)[1];
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
