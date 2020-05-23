# KVM RDTSC timer stabilizer

This project aims to stabilize and minimize the perceived time difference of 2 RDTSC calls and a vmexit (cpuid specifically) in programs running inside a KVM virtual machine.

You may need to configure `constant_tsc_offset` value, which is at 1000 by default. On AMD Ryzen platform, value of ~1600 is rather optimal. Increasing it will make the time difference lower, but there is a risk of backwards time shift, which destabilizes the running operating system.

The current goals are to improve usability (multiple KVM instance support), and efficiency (stabilized value is still rather volatile so it is impossible to consistently pass VM detection tests)
