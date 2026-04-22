#define SEC(name) __attribute__((section(name), used))

static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;

struct {
    int (*type)[1];
    int *key;
    int *value;
    int (*max_entries)[1];
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
