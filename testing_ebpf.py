#!/usr/bin/python2.7
# The "python-bcc" package is a module for Python 2.7

"""
   Testing the Linux kernel's eBPF probing using the IO Visor BPF Compiler
   Collection (BCC).
"""

import sys
import argparse
from time import sleep, strftime

# Import the IO Visor BPF Compiler Collection (BCC)
from bcc import BPF

# Events to watch:

collateral_events = [
    {'func': 'kmalloc_order_trace',
     'probe': 'prb_eBPF_kmalloc_order_trace_return',
     'count': 'global_var_cnt_kmalloc_order_trace'},

    {'func': '__kmalloc',
     'probe': 'prb_eBPF___kmalloc_return',
     'count': 'global_var_cnt___kmalloc'},

    {'func': '__do_kmalloc_node',
     'probe': 'prb_eBPF___do_kmalloc_node_return',
     'count': 'global_var_cnt___do_kmalloc_node'},

    {'func': 'kmem_cache_alloc',
     'probe': 'prb_eBPF_kmem_cache_alloc_return',
     'count': 'global_var_cnt_kmem_cache_alloc'},

    {'func': 'kmem_cache_alloc_trace',
     'probe': 'prb_eBPF_kmem_cache_alloc_trace_return',
     'count': 'global_var_cnt_kmem_cache_alloc_trace'},

    {'func': 'malloc',
     'probe': 'prb_eBPF_malloc_return',
     'count': 'global_var_cnt_malloc'},

    {'func': 'kfree',
     'probe': 'prb_eBPF_kfree_return',
     'count': 'global_var_cnt_kfree'},

    {'func': 'kmem_cache_reap',
     'probe': 'prb_eBPF_kmem_cache_reap_return',
     'count': 'global_var_cnt_kmem_cache_reap'},

    {'func': 'kmem_cache_free',
     'probe': 'prb_eBPF_kmem_cache_free_return',
     'count': 'global_var_cnt_kmem_cache_free'},

    {'func': 'kmem_cache_destroy',
     'probe': 'prb_eBPF_kmem_cache_destroy_return',
     'count': 'global_var_cnt_kmem_cache_destroy'},

    {'func': 'kmem_cache_shrink',
     'probe': 'prb_eBPF_kmem_cache_shrink_return',
     'count': 'global_var_cnt_kmem_cache_shrink'}
]


def main():
    """Main program."""

    if not sys.platform.startswith('linux'):
        sys.stderr.write('This program probes only the Linux kernel\n')
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Show Linux compact_zone() compaction of fragments",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument(
        "-n", "--number-iters", default=1, type=int,
        help="Sample the kernel probes this number of iterations")
    parser.add_argument(
        "-i", "--interval", default=1, type=int,
        help="Sample the kernel probes every this interval, in seconds")
    args = parser.parse_args()

    bpf_obj = run_bpf_probe()
    print_bpf_probes_results(bpf_obj, args.number_iters, args.interval)


def run_bpf_probe():
    """
       Set the extended BPF probe on Linux's compact_zone() function.
       Returns the BPF object created.
    """
    # debug_level = 0x3    # 0x3: dump LLVM IR and BPF byte code to stderr
    debug_level = 0x0      # debug 0x0 = no debug

    bpf = BPF(src_file="eBPF_c_probe.c", debug=debug_level)

    # ebpf_code = bpf.dump_func(func_name="prb_eBPF_compact_zone_entry")

    assert len(bpf["global_var_total_accum_nsec"]) == 1, \
        "Expected a global variable in BPF that be a scalar, ie., of length 1"

    all_attacheable_ksyms = get_all_attacheable_ksyms()

    # our BPF probe will only work for a kernel point which is not executed
    # concurrently, if not it will fail. Of course, you can use other
    # data structures in the BPF probe that can make it work concurrently.
    synchr_non_concurrent_kpoint = "compact_zone"
    if synchr_non_concurrent_kpoint not in all_attacheable_ksyms:
        sys.exit("ERROR: '{}' is not an attacheable symbol"
                 .format(synchr_non_concurrent_kpoint))

    bpf.attach_kprobe(event=synchr_non_concurrent_kpoint,
                      fn_name="prb_eBPF_compact_zone_entry")
    bpf.attach_kretprobe(event=synchr_non_concurrent_kpoint,
                         fn_name="prb_eBPF_compact_zone_return")

    # these are collateral events we want to know if they happen at the same
    # time as the main event above, and relatively, how frequently they happen
    # when the main probed events (above) are happening.
    for collateral_event in collateral_events:
        symbol = collateral_event['func']
        if symbol not in all_attacheable_ksyms:
            sys.stderr.write("Ignoring '{}': not attacheable\n".format(symbol))
            continue

        try:
            bpf.attach_kretprobe(event=symbol,
                                 fn_name=collateral_event['probe'])

            assert len(bpf[collateral_event['count']]) == 1, \
              "Var '{}' must be a scalar.".format(collateral_event['count'])
            sys.stderr.write("Attached to '{}'\n".format(symbol))
        except Exception as exc:
            sys.stderr.write("Attaching to {}: {}\n".format(symbol, exc))

    return bpf


def print_bpf_probes_results(bpf, num_iterations, sleep_secs):
    """
       Print the results of the eBPF probes for 'num_iterations' iterations,
       sleeping 'sleep_secs' seconds between iterations.
    """

    for sample in xrange(1, num_iterations + 1):
        sleep(sleep_secs)

        print "---- new sample: {} at {}".format(sample, strftime("%D %T"))
        # TODO: fix the trade-off between the two choices:
        #       1. either print each BPF statistic, and then clear it, and so
        #          on -so that there is a slight desynchronization between the
        #           first statistic that was reported, and the last one-; or
        #       2. save the values of all BPF statistics to temporary copies,
        #          clear those BPF statistics (trying to clear all together),
        #          and then print the temporary copies of those statistics
        bpf["delay_dist"].print_log2_hist("usecs")
        bpf["delay_dist"].clear()

        # All the direct iterations on BPF tables return ctypes values (like
        # c_int, c_ulong, etc), which we unwrap here by the .value property and
        # divide by 1000 (microseconds) since the histogram in C in the BPF
        # probe also divided the nanoseconds by 1000, so all will report in the
        # same unit of time

        total_accum_nsec = bpf["global_var_total_accum_nsec"].values()[0]
        print "total_accum_usec = {:.0f}".format(total_accum_nsec.value / 1000)
        bpf["global_var_total_accum_nsec"].clear()

        for k, val in bpf["total_accum_nsec_per_order"].items():
            print "total_accum_usec[order = {}] = " "{:.0f}".format(
                k.value, val.value / 1000
            )
        bpf["total_accum_nsec_per_order"].clear()

        for collateral_event in collateral_events:
            concur_kmallocs = bpf[collateral_event['count']].values()[0]
            print "{} while compaction = {}".format(
                collateral_event['func'], concur_kmallocs.value
            )
            bpf[collateral_event['count']].clear()

        sys.stdout.flush()


def get_all_attacheable_ksyms():
    """
       Get the list of all attacheable ksymbols in the running kernel,
       from /proc/kallsyms. (Note: checking against this list is
       recommendable because the ksymbols in different kernel versions
       needn't be the same. E.g., 'kmem_cache_reap' exists in some versions
       of the kernel, but not in newer versions, so attaching to it succeeds
       in the old versions but raises an exception in the new ones.
    """
    result = []
    with open("/proc/kallsyms", "r") as kern_ksyms:
        for line in kern_ksyms:
            line.rstrip('\n')
            tokens = line.split()
            if len(tokens) == 3 and tokens[1] in ['T', 't', 'U', 'u']:
                result.append(tokens[2])

    return result


if __name__ == '__main__':
    main()
