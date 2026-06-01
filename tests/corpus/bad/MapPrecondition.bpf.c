#define SEC(name) __attribute__((section(name), used))

SEC("test")
int threshold_check(void *ctx) {
    volatile long input = 150;
    if (input > 100)
        return 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
