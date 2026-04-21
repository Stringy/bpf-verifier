#define SEC(name) __attribute__((section(name), used))

SEC("test")
int add_regs(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
