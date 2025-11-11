// hello_bpf.c
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_execve")
int hello_bpf(struct pt_regs *ctx) {
    char msg[] = "Hello, eBPF World!\n";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
