# Testing the Linux kernel eBPF probes using the IO Visor BPF Compiler Collection (BCC)

Testing the Linux kernel eBPF probes using the IO Visor BPF Compiler
Collection (BCC), for counting certain collaterial events (kernel
function calls) only when another kernel function (`compact_zone_order`)
is running.

# WIP

This project is a *work in progress*. The implementation is *incomplete* and
subject to change. The documentation can be inaccurate.

# To run:

This script counts the occurrences of certain collaterial events
(kernel function calls), only when another kernel function,
`compact_zone_order`, is running the wrapper:

     # cd <...>/directory-of-this-project/
     # sh example.sh
       total_accum_usec = 0
       kmalloc_order_trace while compaction = 0
       __kmalloc while compaction = 0
       __do_kmalloc_node while compaction = 0
       kmem_cache_alloc while compaction = 0
       kmem_cache_alloc_trace while compaction = 0
       malloc while compaction = 0
       kfree while compaction = 0
       kmem_cache_reap while compaction = 0
       kmem_cache_free while compaction = 0
       kmem_cache_destroy while compaction = 0
       kmem_cache_shrink while compaction = 0

# Required libraries

[Follow these instructions to install the required libraries](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

This script has been tested with a 4.3.3, a 4.4, and a 5.0.1 kernels.

You may need to increase the max value for `ulimit -l`, like in

     ulimit -l 10240

if you receive an error like:

     eBPF_c_probe.c:85:1: error: could not open bpf map: Operation not permitted

although newer versions of the IO Visor BCC may automatically set this, preventing this issue. (See [BCC issue 279](https://github.com/iovisor/bcc/pull/279) for more details.)

# Extra links

The BCC is a recent wrapper (the project itself started in [May 2015](https://github.com/iovisor/bcc/graphs/contributors))
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

This documents explains kprobes:

      https://www.kernel.org/doc/Documentation/kprobes.txt

More background information about IO Visor can be found here:

      https://www.iovisor.org/resources/blog

and some of its objectives (which rely technically on eBPF) are:

      https://www.iovisor.org/news/blogs/2015/08/what-are-implications-io-visor-project-and-why-it-matters

      https://www.iovisor.org/news/blogs/2015/08/programmable-io-across-virtual-and-physical-infrastructures

