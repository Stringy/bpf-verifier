#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int helper_return(void *ctx) {
    return (int)bpf_ktime_get_ns();
}

char LICENSE[] SEC("license") = "GPL";
