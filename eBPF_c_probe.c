#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/*
 * This is an extended BPF kernel module, with some probes, for the IOVisor
 * BPF Compiler Collection (BCC).
 *
 * You should not try to compile directly this code, for its compilation is
 * requested by the BCC. BCC also determines the point in the kernel to which
 * the probes in this module will attach, and instructs these attachments.
 *
 * In our case, the point is only called under one thread at a time, ie.,
 * there is no concurrent usage of the probe point, so the probe can't be
 * trigerred concurrently either.
 */

BPF_HISTOGRAM(delay_dist);
BPF_TABLE("array", int, u64, global_var_time_at_entry, 2);


u64 get_time_at_entry()
{
    u32 array_index = 0;
    u64 *current_time_ptr = global_var_time_at_entry.lookup(&array_index);

    // the eBPF probe runs in kernel mode, so the kernel eBPF verifier is
    // very strict (for safety and stability), and will reject BPF
    // instructions with implicit assumptions, like that a pointer is not
    // null: you need to make explicit the veracity that a pointer is not
    // null, otherwise the kernel verifier will reject it.

  return (current_time_ptr)? *current_time_ptr: 0;
}


void set_time_at_entry(u64 new_value)
{
     u32 array_index = 0;
     u64 *ptr_time_at_entry = global_var_time_at_entry.lookup(&array_index);

     // same as comment above that the kernel verifier requires to check
     // explicitly for implicit assumptions
     if (ptr_time_at_entry)
         *ptr_time_at_entry = new_value;
}


int my_eBPF_probe_do_entry(struct pt_regs *ctx)
{
     u64 time_at_entry = get_time_at_entry();

     if (time_at_entry != 0) {
         // bpf_trace_printk() should only be called in a debug, non-prod
         // kernel
         // bpf_trace_printk("lost a return probe to clear 'time_at_entry'\\n");
         ;
     }

     // store the new time in the global variables array
     time_at_entry = bpf_ktime_get_ns();
     set_time_at_entry(time_at_entry);

     return 0;
}


int my_eBPF_probe_do_return(struct pt_regs *ctx)
{
     u64 time_at_entry = get_time_at_entry();

     if (time_at_entry == 0) {
         // time_at_entry was not recorded at the entry point.
         // Skip this call and do nothing
         // bpf_trace_printk("lost an entry probe to set 'time_at_entry'\\n");
         // bpf_trace_printk() should only be called in a debug, non-prod
         // kernel
         ;
     } else {
         u64 delta = bpf_ktime_get_ns() - time_at_entry;
         delay_dist.increment(bpf_log2l(delta / 1000));

         // clear the (saved) time in the global variables array
         set_time_at_entry(0);
     }

     return 0;
}
