make M=arch/x86/kvm
cp -f arch/x86/kvm/kvm-intel.ko /usr/lib/modules/`uname -r`/kernel/arch/x86/kvm/
cp -f arch/x86/kvm/kvm.ko /usr/lib/modules/`uname -r`/kernel/arch/x86/kvm/
rmmod kvm_intel
rmmod kvm
insmod arch/x86/kvm/kvm.ko
insmod arch/x86/kvm/kvm-intel.ko
