#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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
