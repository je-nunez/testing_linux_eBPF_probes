#!/usr/bin/python

"""Testing the Linux kernel's eBPF probing using the IOVisor BPF Compiler Collection (BCC)."""

# Import the IOVisor BPF Compiler Collection (BCC)
from bcc import BPF

def main():
    """Main program."""

    debug_level = 0x3    # debug 0x3 = print LLVM IR and erreBPF byte code to stderr

    bpf = BPF(src_file="eBPF_c_probe.c", debug=debug_level)
    ebpf_code = bpf.dump_func(func_name="my_eBPF_probe")
    print ebpf_code

    # bpf.attach_kprobe(event="... kernel event here ...", fn_name="my_eBPF_probe")

if __name__ == '__main__':
    main()
