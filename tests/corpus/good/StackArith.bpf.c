#define SEC(name) __attribute__((section(name), used))

SEC("test")
int stack_arith(void *ctx) {
    volatile long a = 10;
    volatile long b = 20;
    volatile long c = 30;
    return (int)(a + b + c);
}

char LICENSE[] SEC("license") = "GPL";
