#define SEC(name) __attribute__((section(name), used))

SEC("test")
int chained_branch(void *ctx) {
    volatile int x = 42;

    if (x > 100)
        return 4;
    else if (x > 50)
        return 3;
    else if (x > 25)
        return 2;
    else
        return 1;
}

char LICENSE[] SEC("license") = "GPL";
