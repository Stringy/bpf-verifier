#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int ktime_get_ns(void *ctx) {
    unsigned long long ts = bpf_ktime_get_ns();
    if (ts > 1000000)
        return 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
