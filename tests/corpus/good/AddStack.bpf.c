#define SEC(name) __attribute__((section(name), used))

SEC("test")
int add_stack(void *ctx) {
    /* volatile forces stack usage */
    volatile int a = 10;
    volatile int b = 32;
    return a + b;
}

char LICENSE[] SEC("license") = "GPL";
