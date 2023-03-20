#include "kernel_rr.h"

static bool in_record = false;

static rr_event_log *rr_event_log_head = NULL;
static rr_event_log *rr_event_log_queue = NULL;


static void rr_insert_event_log(rr_event_log *event)
{
    if (rr_event_log_queue == NULL) {
        rr_event_log_head = event;
        rr_event_log_queue = event;
    } else {
        rr_event_log_queue->next = rr_event_log_queue;
        rr_event_log_queue = rr_event_log_queue->next;
    }
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

    rr_insert_event_log(event_log);
}


static void handle_event_interrupt(struct kvm_vcpu *vcpu, void *opaque)
{
    struct kvm_regs *regs = kmalloc(sizeof(struct kvm_regs), GFP_KERNEL);
    rr_event_log *event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    rr_interrupt *int_log = kmalloc(sizeof(rr_syscall), GFP_KERNEL);

    struct kvm_interrupt *irq = (struct kvm_interrupt *)opaque;

    kvm_arch_vcpu_ioctl_get_regs(vcpu, regs);
    int_log->regs = regs;
    int_log->vector = irq->irq;

    event_log->event.interrupt = int_log;
    event_log->type = EVENT_TYPE_INTERRUPT;

    rr_insert_event_log(event_log);
}

void rr_set_in_record(bool record)
{
    in_record = record;

    if (!in_record) {
        rr_event_log *event = rr_event_log_head;
        printk(KERN_WARNING "=== Report recorded events ===\n");
        while (event) {
            printk(KERN_WARNING "Recorded event: vector=%d\n", event->event.interrupt->vector);
            event = event->next;
        }
    }
}

bool rr_in_record(void)
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
