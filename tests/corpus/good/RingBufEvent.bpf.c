#define SEC(name) __attribute__((section(name), used))

static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;

struct {
    int (*type)[27];
    int (*max_entries)[4096];
} events SEC(".maps");

struct event {
    unsigned int type;
    unsigned int flags;
};

SEC("test")
int ringbuf_event(void *ctx) {
    struct event *e = (struct event *)bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 1;
    e->type = 7;
    e->flags = 0xFF;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
