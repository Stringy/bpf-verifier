#define SEC(name) __attribute__((section(name), used))

static unsigned int (*bpf_get_prandom_u32)(void) = (void *)7;

SEC("test")
int get_prandom(void *ctx) {
    unsigned int r = bpf_get_prandom_u32();
    return (int)(r & 0xFF);
}

char LICENSE[] SEC("license") = "GPL";
