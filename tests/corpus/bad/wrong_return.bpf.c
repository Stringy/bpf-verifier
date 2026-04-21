#define SEC(name) __attribute__((section(name), used))

SEC("test")
int wrong_return(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
