#define SEC(name) __attribute__((section(name), used))

SEC("test")
int early_return(void *ctx) {
    volatile int x = 42;
    volatile int y = 10;

    if (x > 100)
        return 1;

    if (y > 100)
        return 2;

    if (x + y > 100)
        return 3;

    return x + y;
}

char LICENSE[] SEC("license") = "GPL";
