#define SEC(name) __attribute__((section(name), used))

SEC("test")
int branch_gt(void *ctx) {
    /* volatile forces stack usage */
    volatile int x = 10;
    if (x > 5)
        return 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
