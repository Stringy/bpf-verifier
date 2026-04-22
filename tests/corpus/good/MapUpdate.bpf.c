#define SEC(name) __attribute__((section(name), used))

static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) = (void *)2;

struct {
    int (*type)[1];
    int *key;
    int *value;
    int (*max_entries)[1];
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
