#define SEC(name) __attribute__((section(name), used))

SEC("test")
int off_by_one(void *ctx) {
    /* volatile forces stack usage */
    volatile int a = 10;
    volatile int b = 32;
    return a + b;
}

char LICENSE[] SEC("license") = "GPL";
