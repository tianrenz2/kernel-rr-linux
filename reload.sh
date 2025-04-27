#!/bin/bash
rmmod kvm_intel
rmmod kvm
insmod arch/x86/kvm/kvm.ko rr_disable_avx=1
insmod arch/x86/kvm/kvm-intel.ko rr_trap_rdtsc=1
