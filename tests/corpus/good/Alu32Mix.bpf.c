#define SEC(name) __attribute__((section(name), used))

SEC("test")
int alu32_mix(void *ctx) {
    volatile int a = 100;
    volatile int b = 50;
    /* Mix of 32-bit operations */
    int sum = a + b;
    int diff = a - b;
    return sum - diff;
}

char LICENSE[] SEC("license") = "GPL";
