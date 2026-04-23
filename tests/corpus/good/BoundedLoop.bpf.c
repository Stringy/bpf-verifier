#define SEC(name) __attribute__((section(name), used))

SEC("test")
int bounded_loop(void *ctx) {
    volatile int sum = 0;
    /* BPF bounded loop — compiler unrolls or emits a backward branch */
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 5; i++) {
        sum += i;
    }
    return sum;
}

char LICENSE[] SEC("license") = "GPL";
