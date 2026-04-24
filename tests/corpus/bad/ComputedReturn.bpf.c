#define SEC(name) __attribute__((section(name), used))

SEC("test")
int computed_return(void *ctx) {
    volatile int x = 3;
    volatile int y = 4;
    return x + y;
}

char LICENSE[] SEC("license") = "GPL";
