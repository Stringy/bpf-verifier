#define SEC(name) __attribute__((section(name), used))

SEC("test")
int mul_imm(void *ctx) {
    /* volatile forces stack usage */
    volatile int x = 6;
    return x * 7;
}

char LICENSE[] SEC("license") = "GPL";
