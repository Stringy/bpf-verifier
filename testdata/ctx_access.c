// ctx_access.c — Tests context field access validation.
//
// Accesses ctx->len which is a valid field for socket_filter (__sk_buff).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket_filter")
int check_len(struct __sk_buff *ctx) {
    if (ctx->len > 100)
        return 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
