#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int stack_local(void *ctx) {
    /* volatile forces the compiler to actually use the stack */
    volatile int x = 42;
    return x;
}

char LICENSE[] SEC("license") = "GPL";
