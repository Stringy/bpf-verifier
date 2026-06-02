#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int stack_arith(void *ctx) {
    volatile long a = 10;
    volatile long b = 20;
    volatile long c = 30;
    return (int)(a + b + c);
}

char LICENSE[] SEC("license") = "GPL";
