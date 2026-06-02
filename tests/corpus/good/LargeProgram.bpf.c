#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("test")
int large_program(void *ctx) {
    volatile int a = 1, b = 2, c = 3, d = 4, e = 5;
    volatile int f = 6, g = 7, h = 8, i = 9, j = 10;
    volatile int k = 11, l = 12, m = 13, n = 14, o = 15;
    volatile int p = 16, q = 17, r = 18, s = 19, t = 20;
    volatile int u = 21, v = 22, w = 23, x = 24, y = 25;
    volatile int z = 26;

    return a + b + c + d + e + f + g + h + i + j
         + k + l + m + n + o + p + q + r + s + t
         + u + v + w + x + y + z;
}

char LICENSE[] SEC("license") = "GPL";
