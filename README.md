# Testing the Linux kernel eBPF probes using the IO Visor BPF Compiler Collection (BCC)

Testing the Linux kernel eBPF probes using the IO Visor BPF Compiler Collection (BCC)

The Linux kernel eBPF is officially part of the kernel since 3.15, released on 8 June
2014. The BCC is a very recent wrapper (the project itself started in [May 2015](https://github.com/iovisor/bcc/graphs/contributors))
over eBPF, using the library `libbcc.so`. The source code of the BCC module is at

      https://github.com/iovisor/bcc

Some links explaining the eBPF probes in the kernel are:

      (Formal documentation, including also an explanation of what the eBPF kernel
       verifier explicitly ensures on the BPF code it validates.)

      https://www.kernel.org/doc/Documentation/networking/filter.txt

      https://lwn.net/Articles/603983/   (and many others in LWN.net)

      (Brendan Gregg's website)

      http://www.brendangregg.com/blog/2015-05-15/ebpf-one-small-step.html

      http://www.brendangregg.com/blog/2015-09-22/bcc-linux-4.3-tracing.html

      (Suchakrapani Datt Sharma's blog)

      https://suchakra.wordpress.com/2015/05/18/bpf-internals-i/

To see the kernel probes (`kprobes`) in use, do a:

      cat /sys/kernel/debug/kprobes/list

More background information about IO Visor can be found here:

      https://www.iovisor.org/resources/blog

and some of its objectives (which rely technically on eBPF) are:

      https://www.iovisor.org/news/blogs/2015/08/what-are-implications-io-visor-project-and-why-it-matters

      https://www.iovisor.org/news/blogs/2015/08/programmable-io-across-virtual-and-physical-infrastructures

# WIP

This project is a *work in progress*. The implementation is *incomplete* and
subject to change. The documentation can be inaccurate.

# Required libraries

[Follow these instructions to install the required libraries](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

E.g., at least for Red Hat / Fedora, besides a Linux kernel newer than 4.1, you need to install:

     yum install libbcc libbcc-examples python-bcc

This script has been tested with a 4.3.3 kernel.

