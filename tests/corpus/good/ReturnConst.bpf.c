#define SEC(name) __attribute__((section(name), used))

SEC("test")
int return_const(void *ctx) {
    return 7;
}

char LICENSE[] SEC("license") = "GPL";
