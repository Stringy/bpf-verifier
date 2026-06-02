#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int wrong_op(void *ctx) {
    return 5;
}

char LICENSE[] SEC("license") = "GPL";
