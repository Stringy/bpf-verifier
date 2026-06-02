#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int wrong_width(void *ctx) {
    volatile char a = 1;
    volatile short b = 2;
    return (int)(a + b);
}

char LICENSE[] SEC("license") = "GPL";
