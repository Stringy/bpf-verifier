#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int bitwise_and(void *ctx) {
    /* volatile forces the compiler to actually use the stack */
    volatile int x = 0xff;
    return x & 0x0f;
}

char LICENSE[] SEC("license") = "GPL";
