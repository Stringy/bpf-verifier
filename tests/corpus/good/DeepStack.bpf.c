#define SEC(name) __attribute__((section(name), used))

SEC("test")
int deep_stack(void *ctx) {
    /* Use lots of stack space with volatile to prevent optimisation */
    volatile long a = 1;
    volatile long b = 2;
    volatile long c = 3;
    volatile long d = 4;
    volatile long e = 5;
    volatile long f = 6;
    volatile long g = 7;
    volatile long h = 8;
    volatile long i = 9;
    volatile long j = 10;
    return (int)(a + b + c + d + e + f + g + h + i + j);
}

char LICENSE[] SEC("license") = "GPL";
