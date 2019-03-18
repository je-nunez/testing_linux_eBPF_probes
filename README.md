# Testing the Linux kernel eBPF probes using the IO Visor BPF Compiler Collection (BCC)

Testing the Linux kernel eBPF probes using the IO Visor BPF Compiler
Collection (BCC), for counting certain collaterial events (kernel
function calls) only when another kernel function (`compact_zone`)
is running.

# WIP

This project is a *work in progress*. The implementation is *incomplete* and
subject to change. The documentation can be inaccurate.

# To run:

The script in this project uses eBPF to count the occurrences of certain
collaterial events (kernel function calls), only when another kernel
function, `compact_zone`, is running. I.e., it is to count the occurrences
of those collateral events only when certain kernel function is running.

E.g., to generate some load, we can use Mel Gorman's MMTests tests, at
[https://github.com/gormanm/mmtests](https://github.com/gormanm/mmtests),
(e.g., `run-mmtests.sh --run-monitor --config configs/config-global-dhp__workload_thpfioscale-madvhugepage ...`),
and then, measuring with this script:

     # cd <...>/directory-of-this-project/
     # # call the wrapper example.sh script in this project:
     # sh example.sh
       ...
       ---- new sample: 34 at <time>
            usecs               : count     distribution
                0 -> 1          : 0        |                                        |
                2 -> 3          : 0        |                                        |
                4 -> 7          : 0        |                                        |
                8 -> 15         : 0        |                                        |
               16 -> 31         : 0        |                                        |
               32 -> 63         : 0        |                                        |
               64 -> 127        : 0        |                                        |
              128 -> 255        : 0        |                                        |
              256 -> 511        : 0        |                                        |
              512 -> 1023       : 0        |                                        |
             1024 -> 2047       : 4        |****************************************|
             2048 -> 4095       : 0        |                                        |
             4096 -> 8191       : 0        |                                        |
             8192 -> 16383      : 0        |                                        |
            16384 -> 32767      : 1        |**********                              |
            32768 -> 65535      : 1        |**********                              |
            65536 -> 131071     : 0        |                                        |
           131072 -> 262143     : 0        |                                        |
           262144 -> 524287     : 1        |**********                              |
       total_accum_usec = 328598
       total_accum_usec[order = 2175450592] = 328598
       kmalloc_order_trace while compaction = 0
       __kmalloc while compaction = 13144
       __do_kmalloc_node while compaction = 0
       kmem_cache_alloc while compaction = 20514
       kmem_cache_alloc_trace while compaction = 10049
       malloc while compaction = 0
       kfree while compaction = 48336
       kmem_cache_reap while compaction = 0
       kmem_cache_free while compaction = 23239
       kmem_cache_destroy while compaction = 0
       kmem_cache_shrink while compaction = 0
       ---- new sample: 35 at <time + 60 seconds>
            usecs               : count     distribution
                0 -> 1          : 0        |                                        |
                2 -> 3          : 0        |                                        |
                4 -> 7          : 0        |                                        |
                8 -> 15         : 0        |                                        |
               16 -> 31         : 0        |                                        |
               32 -> 63         : 0        |                                        |
               64 -> 127        : 0        |                                        |
              128 -> 255        : 0        |                                        |
              256 -> 511        : 0        |                                        |
              512 -> 1023       : 0        |                                        |
             1024 -> 2047       : 14       |****************************************|
             2048 -> 4095       : 4        |***********                             |
             4096 -> 8191       : 1        |**                                      |
             8192 -> 16383      : 0        |                                        |
            16384 -> 32767      : 1        |**                                      |
            32768 -> 65535      : 0        |                                        |
            65536 -> 131071     : 1        |**                                      |
       total_accum_usec = 127966
       total_accum_usec[order = 2175450592] = 127966
       kmalloc_order_trace while compaction = 0
       __kmalloc while compaction = 463
       __do_kmalloc_node while compaction = 0
       kmem_cache_alloc while compaction = 8756
       kmem_cache_alloc_trace while compaction = 14490
       malloc while compaction = 0
       kfree while compaction = 22900
       kmem_cache_reap while compaction = 0
       kmem_cache_free while compaction = 1680
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

The Cilium project -at [https://github.com/cilium/cilium](https://github.com/cilium/cilium)- relies on eBPF to provide network load-balancing and security to processes and containers.

