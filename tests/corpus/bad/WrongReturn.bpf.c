#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int wrong_return(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
