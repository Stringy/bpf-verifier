#define SEC(name) __attribute__((section(name), used))

SEC("test")
int wrong_op(void *ctx) {
    return 5;
}

char LICENSE[] SEC("license") = "GPL";
