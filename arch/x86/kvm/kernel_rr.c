#include "kernel_rr.h"

int in_record = 0;

rr_event_log *rr_event_log_head = NULL;
rr_event_log *rr_event_log_tail = NULL;


static void rr_insert_event_log(rr_event_log *event)
{
    if (rr_event_log_tail == NULL) {
        rr_event_log_head = event;
        rr_event_log_tail = event;
    } else {
        rr_event_log_tail->next = event;
        rr_event_log_tail = rr_event_log_tail->next;
    }

    rr_event_log_tail->next = NULL;
}


static void handle_event_syscall(struct kvm_vcpu *vcpu, void *opaque)
{
    struct kvm_regs *regs = kmalloc(sizeof(struct kvm_regs), GFP_KERNEL);
    rr_event_log *event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    rr_syscall *syscall_log = kmalloc(sizeof(rr_syscall), GFP_KERNEL);

    kvm_arch_vcpu_ioctl_get_regs(vcpu, regs);
    syscall_log->regs = regs;

    event_log->event.syscall = syscall_log;
    event_log->type = EVENT_TYPE_SYSCALL;
    event_log->next = NULL;

    rr_insert_event_log(event_log);
}

static void handle_event_interrupt(struct kvm_vcpu *vcpu, void *opaque)
{

    struct kvm_regs *kvm_regs;
    rr_event_log *event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    rr_interrupt *int_log = kmalloc(sizeof(rr_interrupt), GFP_KERNEL);
    lapic_log *lapic = (lapic_log *)opaque;
    // int r;

	kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL_ACCOUNT);

	rr_store_regs(vcpu);
    
    memcpy(kvm_regs, &vcpu->run->s.regs.regs, sizeof(struct kvm_regs));

    int_log->regs = kvm_regs;
    int_log->lapic = lapic;

    event_log->event.interrupt = int_log;
    event_log->type = EVENT_TYPE_INTERRUPT;

    rr_insert_event_log(event_log);
}

void rr_set_in_record(int record)
{
    in_record = record;

    if (!in_record) {
        rr_event_log *event = rr_event_log_head;
        int event_num = 0;
        printk(KERN_WARNING "=== Report recorded events ===\n");
        while (event != NULL) {
            if (event->event.interrupt) {
                event_num++;
                // printk(KERN_WARNING "Recorded event: vector=%d, ip=%x\n", event->event.interrupt->vector, event->event.interrupt->regs->rax);
            }
            event = event->next;
        }
        printk(KERN_WARNING "Total Event Number: %d\n", event_num);
    }
}

int rr_in_record(void)
{
    return in_record;
}

lapic_log* create_lapic_log(int delivery_mode, int vector, int trig_mode)
{
    lapic_log *log = kmalloc(sizeof(lapic_log), GFP_KERNEL);

    log->delivery_mode = delivery_mode;
    log->vector = vector;
    log->trig_mode = trig_mode;
    
    return log;
}

void rr_record_event(struct kvm_vcpu *vcpu, int event_type, void *opaque)
{
    switch (event_type)
    {
    case EVENT_TYPE_INTERRUPT:
        handle_event_interrupt(vcpu, opaque);
        break;
    case EVENT_TYPE_EXCEPTION:
        break;
    case EVENT_TYPE_SYSCALL:
        handle_event_syscall(vcpu, opaque);
        break;
    default:
        break;
    }
}

unsigned long cached_bp[KVM_NR_DB_REGS] = {0, 0, 0, 0};

int rr_handle_breakpoint(struct kvm_vcpu *vcpu)
{
    // int i, r;
    // struct kvm_guest_debug dbg;

    // for (i = 0; i < KVM_NR_DB_REGS; ++i) {
    //     cached_bp[i] = vcpu->arch.eff_db[i];
    //     vcpu->arch.eff_db[i] = 0;
    // }

    // dbg.control = 0; 
    // dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_BLOCKIRQ;

    // rr_do_singlestep(vcpu);
	// printk(KERN_INFO "[rr]Handled breakpoint\n");

    // vcpu->arch.singlestep_rip = kvm_get_linear_rip(vcpu);

	// static_call(kvm_x86_update_exception_bitmap)(vcpu);
    // rr_update_apicv_inhibit(vcpu->kvm);

	// kvm_arch_vcpu_guestdbg_update_apicv_inhibit(vcpu->kvm);
    // kvm_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);

    return 0;
}
EXPORT_SYMBOL_GPL(rr_handle_breakpoint);

int rr_handle_debug(struct kvm_vcpu *vcpu)
{
    int i;

    for (i = 0; i < KVM_NR_DB_REGS; ++i) {
        vcpu->arch.eff_db[i] = cached_bp[i];
    }

    vcpu->guest_debug &= ~ KVM_GUESTDBG_SINGLESTEP;
    vcpu->guest_debug &= ~ KVM_GUESTDBG_ENABLE;
    vcpu->guest_debug &= ~ KVM_GUESTDBG_BLOCKIRQ;

    printk(KERN_INFO "[rr]Handled debug\n");
   
    return 0;
}
EXPORT_SYMBOL_GPL(rr_handle_debug);
