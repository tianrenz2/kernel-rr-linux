#ifndef __KERNEL_RR_H__
#define __KERNEL_RR_H__

#include <linux/kvm_host.h>

#define EVENT_TYPE_INTERRUPT 0
#define EVENT_TYPE_EXCEPTION 1
#define EVENT_TYPE_SYSCALL   2

typedef struct {
    __u32 vector;
    struct kvm_regs *regs;
} rr_interrupt;

typedef struct {
    int exception_index;
    int error_code;
} rr_exception;

typedef struct {
    struct kvm_regs *regs;
} rr_syscall;

 

typedef struct rr_event_log_t{
    int type;
    union {
        rr_interrupt *interrupt;
        rr_exception *exception;
        rr_syscall  *syscall;
    } event;
    struct rr_event_log_t *next;
} rr_event_log;

typedef struct {
    int delivery_mode;
	int vector;
    int trig_mode;
} lapic_log;

void rr_record_event(struct kvm_vcpu *vcpu, int event_type, void *opaque);
lapic_log* create_lapic_log(int delivery_mode, int vector, int trig_mode);
bool rr_in_record(void);
void rr_set_in_record(bool in_record);

#endif
