#ifndef __KERNEL_RR_H__
#define __KERNEL_RR_H__

#include <linux/kvm_host.h>

#define EVENT_TYPE_INTERRUPT 0
#define EVENT_TYPE_EXCEPTION 1
#define EVENT_TYPE_SYSCALL   2
#define EVENT_TYPE_IO_IN     3
#define EVENT_TYPE_CFU       4

enum REGS {
    ZERO,
    RR_RAX,
    RR_RCX,
	RR_RDX,
	RR_RBX,
	RR_RSP,
	RR_RBP,
	RR_RSI,
	RR_RDI,
	RR_R8,
	RR_R9,
	RR_R10,
	RR_R11,
	RR_R12,
	RR_R13,
	RR_R14,
	RR_R15,
	RR_RIP,
	RR_NR_VCPU_REGS,
};

typedef struct {
    int delivery_mode;
	int vector;
    int trig_mode;
} lapic_log;

typedef struct {
    unsigned long value;
} rr_io_input;

typedef struct {
    unsigned long src_addr;
    unsigned long len;
    u8 data[1024];
} rr_cfu;

typedef struct {
    lapic_log lapic;
} rr_interrupt;

typedef struct {
    int exception_index;
    int error_code;
    unsigned long cr2;
} rr_exception;

typedef struct {
    struct kvm_regs regs;
} rr_syscall;

typedef struct rr_event_log_t{
    int type;
    union {
        rr_interrupt interrupt;
        rr_exception exception;
        rr_syscall  syscall;
        rr_io_input io_input;
        rr_cfu cfu;
    } event;
    struct rr_event_log_t *next;
    uint64_t inst_cnt;
    unsigned long rip;
} rr_event_log;

typedef struct rr_event_list_t {
    rr_event_log *item;
    int length;
} rr_event_list;

struct rr_event_info {
    int event_number;
};

#endif