#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int add_regs(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
