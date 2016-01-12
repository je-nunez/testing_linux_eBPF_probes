#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MY_EBPF_ARRAY_SIZE 1024


BPF_TABLE("array", u32, long, my_circular_array, MY_EBPF_ARRAY_SIZE);

int my_eBPF_probe(struct pt_regs *ctx) {
  // TO DO (needs to fill parameters to this function too)
  u64 array_index = 0;   // a simple test
  return 0;
}

