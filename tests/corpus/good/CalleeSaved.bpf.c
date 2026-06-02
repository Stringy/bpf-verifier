#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int callee_saved(void *ctx) {
    /* Use callee-saved registers with volatile to force spills */
    volatile long r6_save = 10;
    volatile long r7_save = 20;
    volatile long r8_save = 30;
    return (int)(r6_save + r7_save + r8_save);
}

char LICENSE[] SEC("license") = "GPL";
