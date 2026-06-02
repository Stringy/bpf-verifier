#define SEC(name) __attribute__((section(name), used))

static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;

struct {
    int (*type)[27];
    int (*max_entries)[4096];
} events SEC(".maps");

SEC("test")
int ringbuf_write(void *ctx) {
    int *event = (int *)bpf_ringbuf_reserve(&events, sizeof(int), 0);
    if (!event)
        return 1;
    *event = 42;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
