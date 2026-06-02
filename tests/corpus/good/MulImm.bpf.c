#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int mul_imm(void *ctx) {
    /* volatile forces stack usage */
    volatile int x = 6;
    return x * 7;
}

char LICENSE[] SEC("license") = "GPL";
