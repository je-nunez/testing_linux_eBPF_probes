#!/usr/bin/python

"""
   Testing the Linux kernel's eBPF probing using the IOVisor BPF Compiler
   Collection (BCC).
"""

# Import the IOVisor BPF Compiler Collection (BCC)
from bcc import BPF
from time import sleep


def main():
    """Main program."""

    # debug_level = 0x3    # 0x3: dump LLVM IR and erreBPF byte code to stderr
    debug_level = 0x0      # debug 0x0 = no debug

    bpf = BPF(src_file="eBPF_c_probe.c", debug=debug_level)
    # ebpf_code = bpf.dump_func(func_name="my_eBPF_probe_do_entry")

    # our BPF probe will only work for a kernel point which is not executed
    # concurrently, if not it will fail. Of course, you can use other
    # data structures in the BPF probe that can make it work concurrently.
    synchr_non_concurrent_kpoint = "try_to_compact_pages"
    bpf.attach_kprobe(event=synchr_non_concurrent_kpoint,
                      fn_name="my_eBPF_probe_do_entry")
    bpf.attach_kretprobe(event=synchr_non_concurrent_kpoint,
                         fn_name="my_eBPF_probe_do_return")

    # request time to sleep as an argument from the command-line, ie., by
    # using the 'argparse' module
    sleep(60)      # wait for 60 seconds before sampling the results of probe

    bpf["delay_dist"].print_log2_hist("usecs")
    # bpf["delay_dist"].clear()   # not necessary, we exit now


if __name__ == '__main__':
    main()
