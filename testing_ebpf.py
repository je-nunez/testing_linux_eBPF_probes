#!/usr/bin/python

"""
   Testing the Linux kernel's eBPF probing using the IO Visor BPF Compiler
   Collection (BCC).
"""

import sys
import argparse
from time import sleep, strftime

# Import the IO Visor BPF Compiler Collection (BCC)
from bcc import BPF


def main():
    """Main program."""

    if not sys.platform.startswith('linux'):
        sys.stderr.write('This program probes only the Linux kernel\n')
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Show Linux compact_zone_order() compaction of fragments",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument(
        "-n", "--number-iters", default=1, type=int,
        help="Sample the kernel probes this number of iterations")
    parser.add_argument(
        "-i", "--interval", default=1, type=int,
        help="Sample the kernel probes every this interval, in seconds")
    args = parser.parse_args()

    run_bpf_probe(args.number_iters, args.interval)


def run_bpf_probe(num_iterations, sleep_secs):
    """Run the extended BPF probe on Linux's compact_zone_order() function."""

    # debug_level = 0x3    # 0x3: dump LLVM IR and BPF byte code to stderr
    debug_level = 0x0      # debug 0x0 = no debug

    bpf = BPF(src_file="eBPF_c_probe.c", debug=debug_level)

    # ebpf_code = bpf.dump_func(func_name="prb_eBPF_compact_zone_order_entry")

    assert len(bpf["global_var_total_accum_nsec"]) == 1, \
        "Expected a global variable in BPF that be a scalar, ie., of length 1"

    # our BPF probe will only work for a kernel point which is not executed
    # concurrently, if not it will fail. Of course, you can use other
    # data structures in the BPF probe that can make it work concurrently.
    synchr_non_concurrent_kpoint = "compact_zone_order"
    bpf.attach_kprobe(event=synchr_non_concurrent_kpoint,
                      fn_name="prb_eBPF_compact_zone_order_entry")
    bpf.attach_kretprobe(event=synchr_non_concurrent_kpoint,
                         fn_name="prb_eBPF_compact_zone_order_return")

    # these are other collateral events we want to know if they happen at the
    # same time as the main event above, and relatively, how frequently they
    # happen when the main probed events (above) are happening.

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

        {'func': 'kmem_cache_alloc_trace',
         'probe': 'prb_eBPF_kmem_cache_alloc_trace_return',
         'count': 'global_var_cnt_kmem_cache_alloc_trace'},

        {'func': 'malloc',
         'probe': 'prb_eBPF_malloc_return',
         'count': 'global_var_cnt_malloc'}
    ]

    for collateral_event in collateral_events:
        bpf.attach_kretprobe(event=collateral_event['func'],
                             fn_name=collateral_event['probe'])

        assert len(bpf[collateral_event['count']]) == 1, \
            "Var '{}' must be a scalar too.".format(collateral_event['count'])

    # request time to sleep and iterations as arguments from the command-line,
    # e.g., by using the 'argparse' module (the timing to wait is important
    # because there can be no output reported below if there is no activity of
    # the kprobe we attached to in this period of time)
    for sample in xrange(1, num_iterations + 1):
        sleep(sleep_secs)

        print "sample: {} at {}".format(sample, strftime("%D %T"))
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
            print ("total_accum_usec[order = {}] = "
                   "{:.0f}").format(k.value, val.value / 1000)
        bpf["total_accum_nsec_per_order"].clear()

        for collateral_event in collateral_events:
            concur_kmallocs = bpf[collateral_event['count']].values()[0]
            print "{} while compaction = {}".format(collateral_event['func'],
                                                    concur_kmallocs.value)
            bpf[collateral_event['count']].clear()

        sys.stdout.flush()


if __name__ == '__main__':
    main()
