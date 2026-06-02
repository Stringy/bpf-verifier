#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int return_const(void *ctx) {
    return 7;
}

char LICENSE[] SEC("license") = "GPL";
