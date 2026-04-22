#define SEC(name) __attribute__((section(name), used))

static unsigned long long (*bpf_ktime_get_ns)(void) = (void *)5;

SEC("test")
int ktime_get_ns(void *ctx) {
    unsigned long long ts = bpf_ktime_get_ns();
    if (ts > 1000000)
        return 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
