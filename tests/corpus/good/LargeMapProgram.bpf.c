#define SEC(name) __attribute__((section(name), used))

static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    int (*type)[1];
    int *key;
    int *value;
    int (*max_entries)[1];
} my_map SEC(".maps");

SEC("test")
int large_map_program(void *ctx) {
    int total = 0;

    /* Three map lookups with null checks, accumulating values */
    int key1 = 0;
    int *val1 = (int *)bpf_map_lookup_elem(&my_map, &key1);
    if (val1)
        total += *val1;

    int key2 = 1;
    int *val2 = (int *)bpf_map_lookup_elem(&my_map, &key2);
    if (val2)
        total += *val2;

    int key3 = 2;
    int *val3 = (int *)bpf_map_lookup_elem(&my_map, &key3);
    if (val3)
        total += *val3;

    /* Bounds check on the total */
    if (total > 1000)
        total = 1000;

    return total;
}

char LICENSE[] SEC("license") = "GPL";
