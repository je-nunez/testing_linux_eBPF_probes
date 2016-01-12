# Testing the Linux kernel eBPF probes using the IOVisor BPF Compiler Collection (BCC)

Testing the Linux kernel eBPF probes using the IOVisor BPF Compiler Collection (BCC)

Some links explaining the eBPF probes in the kernel are:

      https://lwn.net/Articles/603983/   (and many others in LWN.net)

      (Brendan Gregg's website)

      http://www.brendangregg.com/blog/2015-05-15/ebpf-one-small-step.html

      http://www.brendangregg.com/blog/2015-09-22/bcc-linux-4.3-tracing.html

      (Suchakrapani Datt Sharma's blog)

      https://suchakra.wordpress.com/2015/05/18/bpf-internals-i/

The source code of the BCC module is at

      https://github.com/iovisor/bcc


# WIP

This project is a *work in progress*. The implementation is *incomplete* and
subject to change. The documentation can be inaccurate.

# Required libraries

[Follow these instructions to install the required libraries](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

E.g., at least for Red Hat / Fedora, besides a Linux kernel newer than 4.1, you need to install:

     yum install libbcc libbcc-examples python-bcc

This script has been tested with a 4.3.3 kernel.

