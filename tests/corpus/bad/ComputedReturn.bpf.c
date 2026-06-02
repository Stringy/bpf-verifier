#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int computed_return(void *ctx) {
    volatile int x = 3;
    volatile int y = 4;
    return x + y;
}

char LICENSE[] SEC("license") = "GPL";
