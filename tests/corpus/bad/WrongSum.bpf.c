#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int wrong_sum(void *ctx) {
    volatile long a = 10;
    volatile long b = 20;
    return (int)(a + b);
}

char LICENSE[] SEC("license") = "GPL";
