#!/bin/sh

# See requirements: https://github.com/je-nunez/testing_linux_eBPF_probes#required-libraries

# Take and print samples 1440 times every 60 seconds

./testing_ebpf.py  -n 1440 -i 60  2>&1 | tee -a samples.txt

