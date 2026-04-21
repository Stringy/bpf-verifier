#define SEC(name) __attribute__((section(name), used))

SEC("test")
int stack_local(void *ctx) {
    /* volatile forces the compiler to actually use the stack */
    volatile int x = 42;
    return x;
}

char LICENSE[] SEC("license") = "GPL";
