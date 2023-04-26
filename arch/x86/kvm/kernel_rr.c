#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include <asm/kernel_rr.h>

#include "kernel_rr.h"

int in_record = 0;
int in_replay = 0;

rr_event_log *rr_event_log_head = NULL;
rr_event_log *rr_event_log_tail = NULL;
rr_event_log *rr_event_cur = NULL;

const unsigned long syscall_addr = 0xffffffff8111d0ef;
const unsigned long pf_excep_addr = 0xffffffff8111e449;

static rr_exception* new_rr_exception(int vector, int error_code, unsigned long cr2)
{
    rr_exception *excp_log;

    excp_log = kmalloc(sizeof(rr_exception), GFP_KERNEL);

    excp_log->exception_index = vector;
    excp_log->error_code = error_code;

    return excp_log;
}

__maybe_unused static void rr_print_regs(struct kvm_regs *regs)
{
    printk(KERN_INFO "[RR Print Regs]\n"
           "rax=%llu, rbx=%llu, rcx=%llu, rdx=%llu,"
           "rsi=%llu, rdi=%llu, rsp=%llu, rbp=%llu"
           "rip=%llu",
           regs->rax, regs->rbx, regs->rcx, regs->rdx,
           regs->rsi, regs->rdi, regs->rsp, regs->rbp,
           regs->rip);
}

__maybe_unused static void rr_record_regs(struct kvm_regs *dest_regs, struct kvm_regs *src_regs)
{
    dest_regs->rax = src_regs->rax;
    dest_regs->rbx = src_regs->rbx;
    dest_regs->rcx = src_regs->rcx;
    dest_regs->rdx = src_regs->rdx;
    
    dest_regs->rsi = src_regs->rsi;
    dest_regs->rdi = src_regs->rdi;
    dest_regs->rsp = src_regs->rsp;
    dest_regs->rbp = src_regs->rbp;

    dest_regs->r8 = src_regs->r8;
    dest_regs->r9 = src_regs->r9;
    dest_regs->r10 = src_regs->r10;
    dest_regs->r11 = src_regs->r11;

    dest_regs->r12 = src_regs->r12;
    dest_regs->r13 = src_regs->r13;
    dest_regs->r14 = src_regs->r14;
    dest_regs->r15 = src_regs->r15;

    dest_regs->rip = src_regs->rip;
    dest_regs->rflags = src_regs->rflags;
}

int rr_get_event_list_length(void)
{
    rr_event_log *event = rr_event_log_head;
    int len = 0;

    while (event != NULL) {
        len++;
        event = event->next;
    }

    return len;
}

void rr_copy_to_event_list(struct rr_event_list_t *event_list, int len)
{
    rr_event_log *event = rr_event_log_head;
    event_list->length = 0;

    while (event != NULL) {
        
        event = event->next;
    }
}

rr_event_log rr_get_next_event(void)
{
    rr_event_log *event = kmalloc(sizeof(struct rr_event_log_t), GFP_KERNEL);

    if (rr_event_cur == NULL) {
        return *event;
    }

    memcpy(event, rr_event_cur, sizeof(struct rr_event_log_t));

    rr_event_cur = rr_event_cur->next;

    return *event;
}

static void rr_post_handle_event(struct kvm_vcpu *vcpu, rr_event_log *event)
{
    event->inst_cnt = kvm_get_inst_cnt(vcpu) - vcpu->rr_start_point;
}

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

static void handle_event_exception(struct kvm_vcpu *vcpu, void *opaque)
{
    struct kvm_regs *regs;
    rr_event_log *event_log;
    rr_exception *except;

	regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL_ACCOUNT);
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);

    except = (rr_exception *)opaque;

    switch (except->exception_index) {
        case PF_VECTOR:
            except->error_code = get_rsi(vcpu);
            except->cr2 = vcpu->arch.cr2;
            break;
        default:
            return;
    }

    event_log->type = EVENT_TYPE_EXCEPTION;
    event_log->event.exception = *except;
    event_log->next = NULL;

    rr_post_handle_event(vcpu, event_log);
    rr_insert_event_log(event_log);
}


static void handle_event_syscall(struct kvm_vcpu *vcpu, void *opaque)
{
    struct kvm_regs *regs;
    rr_event_log *event_log;
    rr_syscall *syscall_log;

    regs = kmalloc(sizeof(struct kvm_regs), GFP_KERNEL);
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    syscall_log = kmalloc(sizeof(rr_syscall), GFP_KERNEL);

    rr_get_regs(vcpu, regs);
    syscall_log->regs = *regs;

    event_log->event.syscall = *syscall_log;
    event_log->type = EVENT_TYPE_SYSCALL;
    event_log->next = NULL;

    rr_post_handle_event(vcpu, event_log);
    rr_insert_event_log(event_log);
}

static void handle_event_interrupt(struct kvm_vcpu *vcpu, void *opaque)
{

    struct kvm_regs *regs;
    rr_event_log *event_log;
    rr_interrupt *int_log;
    lapic_log *lapic = (lapic_log *)opaque;

	regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL_ACCOUNT);
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    int_log = kmalloc(sizeof(rr_interrupt), GFP_KERNEL);

    int_log->lapic = *lapic;

    event_log->event.interrupt = *int_log;
    event_log->type = EVENT_TYPE_INTERRUPT;
    event_log->next = NULL;

    rr_post_handle_event(vcpu, event_log);

    if (rr_event_log_tail != NULL && rr_event_log_tail->inst_cnt == event_log->inst_cnt) {
        return;
    }

    rr_insert_event_log(event_log);
}

void rr_set_in_record(struct kvm_vcpu *vcpu, int record)
{
    if (record == in_record) {
        printk(KERN_WARNING "Skip because it's record status is already %d\n", record);
        return;
    }

    in_record = record;

    if (!in_record) {
        rr_event_log *event = rr_event_log_head;
        int event_int_num = 0;
        int event_syscall_num = 0;
        int event_pf_excep = 0;

        printk(KERN_WARNING "=== Report recorded events ===\n");
        while (event != NULL) {
            if (event->type == EVENT_TYPE_INTERRUPT) {
                event_int_num++;
            }

            if (event->type == EVENT_TYPE_SYSCALL) {
                event_syscall_num++;
            }

            if (event->type == EVENT_TYPE_EXCEPTION) {
                printk(KERN_WARNING "except vector=%d error code=%d, addr=%x",
                       event->event.exception.exception_index,
                       event->event.exception.error_code,
                       event->event.exception.cr2);
                event_pf_excep++;
            }

            event = event->next;

        }

        printk(KERN_INFO "syscall=%d, interrupt=%d, pf=%d\n",
               event_syscall_num, event_int_num, event_pf_excep);

        kvm_make_request(KVM_REQ_END_RECORD, vcpu);

        rr_event_cur = rr_event_log_head;

    } else {
        if (rr_event_log_head != NULL) {
            rr_event_log *pre_event = rr_event_log_head;
            rr_event_log *event;

            while (pre_event != NULL) {
                event = pre_event->next;
                kfree(pre_event);
                pre_event = event;
            }

            rr_event_log_head = NULL;
            rr_event_log_tail = NULL;

            printk(KERN_INFO "RR initialized\n");
        }

        kvm_make_request(KVM_REQ_START_RECORD, vcpu);
    }
}

void rr_set_in_replay(struct kvm_vcpu *vcpu, int replay)
{
    in_replay = replay;
}

int rr_in_replay(void)
{
    return in_replay;
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
        handle_event_exception(vcpu, opaque);
        break;
    case EVENT_TYPE_SYSCALL:
        handle_event_syscall(vcpu, opaque);
        break;
    default:
        break;
    }
}

int rr_handle_breakpoint(struct kvm_vcpu *vcpu)
{
    unsigned long addr;

    if (!rr_in_record()) {
        return 0;
    }

    addr = kvm_get_linear_rip(vcpu);

    switch(addr) {
        case syscall_addr:
            rr_record_event(vcpu, EVENT_TYPE_SYSCALL, NULL);
            break;
        case pf_excep_addr:
            rr_record_event(vcpu, EVENT_TYPE_EXCEPTION, new_rr_exception(PF_VECTOR, 0, 0));
            break;
        default:
            break;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(rr_handle_breakpoint);
