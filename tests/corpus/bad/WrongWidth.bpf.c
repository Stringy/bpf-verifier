#define SEC(name) __attribute__((section(name), used))

SEC("test")
int wrong_width(void *ctx) {
    volatile char a = 1;
    volatile short b = 2;
    return (int)(a + b);
}

char LICENSE[] SEC("license") = "GPL";
