#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int wide_stack(void *ctx) {
    /* Use volatile to force actual stack accesses at different widths */
    volatile char a = 1;
    volatile short b = 2;
    volatile int c = 3;
    volatile long d = 4;
    return (int)(a + b + c + d);
}

char LICENSE[] SEC("license") = "GPL";
