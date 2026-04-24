#define SEC(name) __attribute__((section(name), used))

static long (*bpf_ktime_get_ns)(void) = (void *)5;

SEC("test")
int helper_return(void *ctx) {
    return (int)bpf_ktime_get_ns();
}

char LICENSE[] SEC("license") = "GPL";
