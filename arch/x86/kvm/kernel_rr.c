#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include "x86.h"
#include "kvm_cache_regs.h"
#include "kvm_emulate.h"

#include <asm/kernel_rr.h>

#include "kernel_rr.h"

int in_record = 0;
int in_replay = 0;

rr_event_log *rr_event_log_head = NULL;
rr_event_log *rr_event_log_tail = NULL;
rr_event_log *rr_event_cur = NULL;
int total_event_cnt = 0;

rr_mem_access_log *rr_mem_log_head = NULL;
rr_mem_access_log *rr_mem_log_tail = NULL;
rr_mem_access_log *rr_mem_log_cur = NULL;

rr_random *random_cur = NULL;

// const unsigned long syscall_addr = 0xffffffff81200000;
// const unsigned long pf_excep_addr = 0xffffffff8111e369;
// const unsigned long copy_from_iter_addr = 0xffffffff810afc14;
// const unsigned long copy_from_user_addr = 0xffffffff810b4fb8;
// const unsigned long copy_page_from_iter_addr = 0xffffffff810b0b16;
// const unsigned long strncpy_addr = 0xffffffff810cbd51;
// const unsigned long get_user_addr = 0xffffffff81118850;
// const unsigned long strnlen_user_addr = 0xffffffff810cbe4a;
// const unsigned long random_bytes_addr = 0xffffffff810e1e25;

// const unsigned long syscall_addr = 0xffffffff81800000;
// const unsigned long pf_excep_addr = 0xffffffff81800ab0;
// const unsigned long copy_from_iter_addr = 0xffffffff816452a9;
// const unsigned long copy_from_user_addr = 0xffffffff8164c967; 
// const unsigned long copy_page_from_iter_addr = 0xffffffff8100000;
// const unsigned long strncpy_addr = 0xffffffff816c064c; // call   0xffffffff811183e0 <copy_user_enhanced_fast_string>
// const unsigned long get_user_addr = 0xffffffff818fa750;
// const unsigned long strnlen_user_addr = 0xffffffff816c0751;

// == no hypercall
// const unsigned long syscall_addr = 0xffffffff81800000; // info addr entry_SYSCALL_64
// const unsigned long pf_excep_addr = 0xffffffff81741930; // info addr exc_page_fault
// const unsigned long copy_from_iter_addr = 0xffffffff8144af0d; // lib/iov_iter.c:186
// const unsigned long copy_from_user_addr = 0xffffffff814528e7; // lib/usercopy.c:21
// const unsigned long copy_page_from_iter_addr = 0xffffffff8144dd7e;
// const unsigned long strncpy_addr = 0xffffffff81483732; // lib/strncpy_from_user.c:141
// const unsigned long get_user_addr = 0xffffffff81708100; // arch/x86/lib/getuser.S:103
// const unsigned long strnlen_user_addr = 0xffffffff81483832; // lib/strnlen_user.c:115

// const unsigned long random_bytes_addr_start = 0xffffffff81533620; // b _get_random_bytes
// const unsigned long random_bytes_addr_end = 0xffffffff815337c0; // b drivers/char/random.c:382

// == with hypercall
const unsigned long syscall_addr = 0xffffffff81800000; // info addr entry_SYSCALL_64
const unsigned long pf_excep_addr = 0xffffffff81741960; // info addr exc_page_fault
const unsigned long copy_from_iter_addr = 0xffffffff8144af0d; // lib/iov_iter.c:186
const unsigned long copy_from_user_addr = 0xffffffff814528e7; // lib/usercopy.c:21
const unsigned long copy_page_from_iter_addr = 0xffffffff8144dd7e;
const unsigned long strncpy_addr = 0xffffffff81483732; // lib/strncpy_from_user.c:141
const unsigned long get_user_addr = 0xffffffff816c2220; // arch/x86/lib/getuser.S:103
const unsigned long strnlen_user_addr = 0xffffffff8146bb66; // lib/strnlen_user.c:115

const unsigned long random_bytes_addr_start = 0xffffffff81533660; // b _get_random_bytes
const unsigned long random_bytes_addr_end = 0xffffffff81533800; // b drivers/char/random.c:382

const unsigned long last_removed_addr = 0;

const unsigned long uaccess_begin = 0xffffffff811e084c;


// target_ulong cfu_addr1 = 0xffffffff811183e0; // call   0xffffffff811183e0 <copy_user_enhanced_fast_string>
// target_ulong cfu_addr2 = 0xffffffff810afc0d; // call   0xffffffff811183e0 <copy_user_enhanced_fast_string>

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
    // rr_event_log *event = rr_event_log_head;
    // int len = 0;

    // if (rr_event_log_head != NULL)
    //     printk(KERN_INFO "rr log head: %d\n", rr_event_log_head->type);

    // while (event != NULL) {
    //     len++;
    //     event = event->next;
    // }

    // printk(KERN_INFO "event len=%d\n", len);

    // return len;
    return total_event_cnt;
}

int rr_get_mem_log_list_length(void)
{
    rr_mem_access_log *log;
    int len = 0;

    if (rr_mem_log_head == NULL) {
        return 0;
    }

    log = rr_mem_log_head;
    while (log != NULL) {
        len++;
        log = log->next;
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

rr_mem_access_log rr_get_next_mem_log(void)
{
    rr_mem_access_log *log = kmalloc(sizeof(struct rr_mem_access_log_t), GFP_KERNEL);

    if (rr_mem_log_cur == NULL) {
        return *log;
    }

    memcpy(log, rr_mem_log_cur, sizeof(struct rr_mem_access_log_t));

    rr_mem_log_cur = rr_mem_log_cur->next;

    return *log;
}

static int rr_post_handle_event(struct kvm_vcpu *vcpu, rr_event_log *event)
{
    // uint64_t cur_inst = kvm_get_inst_cnt(vcpu);

    // if (!cur_inst) {
    //     event->inst_cnt = 0;
    // } else {
    //     event->inst_cnt = cur_inst - vcpu->rr_start_point - 1;
    // }
    
    unsigned long cnt = kvm_get_inst_cnt(vcpu) - vcpu->rr_start_point;

    if (rr_event_cur != NULL && cnt == rr_event_cur->inst_cnt) {
        return 0;
    }

    event->inst_cnt = cnt;

    return 1;
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


    rr_get_regs(vcpu, regs);

    switch (except->exception_index) {
        case PF_VECTOR:
            except->error_code = get_rsi(vcpu);
            except->cr2 = vcpu->arch.cr2;
            // printk(KERN_INFO "error code: %d\n", except->error_code);
            break;
        default:
            return;
    }

    except->regs = *regs;

    event_log->type = EVENT_TYPE_EXCEPTION;
    event_log->event.exception = *except;
    event_log->next = NULL;

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);
}


static void handle_event_syscall(struct kvm_vcpu *vcpu, void *opaque)
{
    struct kvm_regs *regs;
    rr_event_log *event_log;
    rr_syscall *syscall_log;
    u64 gsbase, kernel_gsbase;
    // struct kvm_segment *seg;

    regs = kmalloc(sizeof(struct kvm_regs), GFP_KERNEL);
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    syscall_log = kmalloc(sizeof(rr_syscall), GFP_KERNEL);
    // seg = kmalloc(sizeof(struct kvm_segment), GFP_KERNEL);

    rr_get_regs(vcpu, regs);

    syscall_log->cr3 = kvm_read_cr3(vcpu);

    // kvm_get_segment(vcpu, seg, VCPU_SREG_GS);

    kvm_get_msr(vcpu, MSR_GS_BASE, &gsbase);
    kvm_get_msr(vcpu, MSR_KERNEL_GS_BASE, &kernel_gsbase);

    syscall_log->regs = *regs;
    syscall_log->msr_gsbase = gsbase;
    syscall_log->kernel_gsbase = kernel_gsbase;

    event_log->event.syscall = *syscall_log;
    event_log->type = EVENT_TYPE_SYSCALL;
    event_log->next = NULL;

    // printk(KERN_INFO "sycall: gsbase=0x%lx, gsbase_kernel=0x%lx\n",
    //        syscall_log->msr_gsbase , syscall_log->kernel_gsbase);

    if (rr_post_handle_event(vcpu, event_log)) {
        rr_insert_event_log(event_log);
    }
    
    rr_mem_log_cur = rr_mem_log_head;
}

static void handle_event_interrupt(struct kvm_vcpu *vcpu, void *opaque)
{

    struct kvm_regs *regs;
    rr_event_log *event_log;
    rr_interrupt *int_log;
    lapic_log *lapic = (lapic_log *)opaque;
    unsigned long rip;

    WARN_ON(is_guest_mode(vcpu));

    regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL_ACCOUNT);
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    int_log = kmalloc(sizeof(rr_interrupt), GFP_KERNEL);

    int_log->lapic = *lapic;

    event_log->event.interrupt = *int_log;
    event_log->type = EVENT_TYPE_INTERRUPT;
    event_log->next = NULL;

    event_log->rip = kvm_arch_vcpu_get_ip(vcpu);

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);
    else
        printk(KERN_INFO "Failed to append int %d\n", event_log->event.interrupt.lapic.vector);
}

static void handle_event_cfu(struct kvm_vcpu *vcpu, void *opaque)
{

    struct kvm_regs *regs;
    struct kvm_sregs *sregs;
    rr_event_log *event_log;
    void *val;
    int ret;
    struct x86_emulate_ctxt *emulate_ctxt;
    rr_cfu *cfu_log;
    int i;
    unsigned long long dest_addr, src_addr;
    unsigned long *cfu_ip = (unsigned long *)opaque;
    unsigned long len;
    bool do_read_mem = false;
    int j;
    __maybe_unused u8 dest_data[4096];

    cfu_log = kmalloc(sizeof(rr_cfu), GFP_KERNEL);

    regs = kmalloc(sizeof(struct kvm_regs), GFP_KERNEL);
    sregs = kmalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);

    event_log->type = EVENT_TYPE_CFU;

    rr_get_regs(vcpu, regs);
    rr_get_sregs(vcpu, sregs);

    emulate_ctxt = vcpu->arch.emulate_ctxt;

    if (*cfu_ip == copy_from_iter_addr) {
        // === Kernel Version 1 ===
        // len = regs->r14;
        // dest_addr = regs->rdi - len;
        // src_addr = regs->rsi - len;
        // === End ===

        // === Kernel Version 2 ===
        len = regs->rdx;
        dest_addr = regs->rdi - len;
        src_addr = regs->rsi - len;
        // === End ===

        do_read_mem = true;
    } else if (*cfu_ip == copy_from_user_addr) {
        // === Kernel Version 1 ===
        // len = regs->rbx;
        // src_addr = regs->rsi - len;
        // dest_addr = regs->rdi - len;
        // === End ===

        // === Kernel Version 1 ===
        len = regs->rbp;
        src_addr = regs->rsi - len;
        dest_addr = regs->rdi - len;
        // === End ===

        do_read_mem = true;
    } else if (*cfu_ip == copy_page_from_iter_addr) {
        len = regs->rbx;
        src_addr = regs->rsi - len;
        dest_addr = regs->rdi - len;
        do_read_mem = true;
    } else if (*cfu_ip == strncpy_addr) {
        // === Kernel version 1 ===
        // len = regs->rax;
        // src_addr = regs->r8;
        // dest_addr = regs->rdi;
        // === End ===

        // === Kernel version 2 ===
        // len = regs->rax;
        // src_addr = regs->rbp;
        // dest_addr = regs->r12;
        // === End ===

        // === Kernel version 3 ===
        len = regs->rax;
        src_addr = regs->rdi;
        dest_addr = regs->r8;
        do_read_mem = true;
    } else if (*cfu_ip == get_user_addr) {
       cfu_log->rdx = regs->rdx;
       cfu_log->src_addr = 0;
       cfu_log->dest_addr = 0;
    //    printk(KERN_INFO "get user log: %lx\n", cfu_log->rdx);
    } else if (*cfu_ip == strnlen_user_addr) {
        cfu_log->len = regs->rax;
        // printk(KERN_INFO "strnlen_user_addr happened: %d\n", cfu_log->len);
    } else if (*cfu_ip == uaccess_begin) {
        cfu_log->src_addr = regs->rax;
        cfu_log->len = sregs->cs.base;
        printk(KERN_INFO "Read from src=0x%lx, dest=0x%lx, len=%lu\n", cfu_log->src_addr, cfu_log->dest_addr, cfu_log->len);
    }

    if (do_read_mem) {
        cfu_log->src_addr = src_addr;
        cfu_log->dest_addr = dest_addr;
        cfu_log->len = len;

        if (cfu_log->len > 4096) {
            printk(KERN_WARNING "Oversized: 0x%lx, %lu, addr=0x%lx\n", dest_addr, cfu_log->len, regs->rip);
        } else {
            // printk(KERN_INFO "Read from src=0x%lx, dest=0x%lx, len=%lu\n", cfu_log->src_addr, cfu_log->dest_addr, cfu_log->len);

            ret = rr_kvm_read_guest_virt(vcpu,
                                      cfu_log->src_addr, cfu_log->data, cfu_log->len,
                                      &emulate_ctxt->exception, PFERR_USER_MASK);

            // ret = rr_kvm_read_guest_virt(vcpu,
            //                           cfu_log->dest_addr, dest_data, cfu_log->len,
            //                           &emulate_ctxt->exception, 0);

            if (ret != X86EMUL_CONTINUE) {
                printk(KERN_WARNING "Failed to read addr 0x%lx, ret %d\n",
                    cfu_log->src_addr, ret);
            }
        }

        // if (strcmp(cfu_log->data, dest_data) == 0) {
        //     printk(KERN_WARNING "read data matched\n");
        // }

        // printk(KERN_INFO "CFU: read from addr=0x%lx, len=%d, ret=%d, rip=0x%lx\n",
        //        cfu_log->dest_addr, len, ret, regs->rip);

        // if (ret != X86EMUL_PROPAGATE_FAULT) {
        //     printk(KERN_WARNING "Failed to read addr 0x%lx, ret %d\n",
        //            cfu_log->dest_addr, ret);
        // }
    }

    event_log->event.cfu = *cfu_log;

    event_log->rip = kvm_arch_vcpu_get_ip(vcpu);

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);

    return;
}

static void handle_event_random_generator(struct kvm_vcpu *vcpu, void *opaque)
{
    struct kvm_regs *regs;
    rr_event_log *event_log;
    rr_random *rand_log;
    struct x86_emulate_ctxt *emulate_ctxt;
    int ret = 0;
    unsigned long rip = kvm_arch_vcpu_get_ip(vcpu);

    if (rip == random_bytes_addr_start) {
        if (random_cur != NULL) {
            printk(KERN_WARNING "Intercept random in middle of a random");
        }

        regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL_ACCOUNT);
        rand_log = kmalloc(sizeof(rr_random), GFP_KERNEL);

        rr_get_regs(vcpu, regs);

        rand_log->len = regs->rsi;
        rand_log->buf = regs->rdi;

        random_cur = rand_log;
    } else {
        rand_log = random_cur;

        if (random_cur == NULL) {
            return;
        }
        
        printk(KERN_INFO "Random read from 0x%lx, len=%d\n", rand_log->buf, rand_log->len);

        event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
        
        event_log->type = EVENT_TYPE_RANDOM;

        emulate_ctxt = vcpu->arch.emulate_ctxt;

        ret = emulate_ctxt->ops->read_emulated(vcpu->arch.emulate_ctxt,
                                            rand_log->buf, rand_log->data, rand_log->len,
                                            &emulate_ctxt->exception);
        if (ret != X86EMUL_PROPAGATE_FAULT) {
            printk(KERN_WARNING "Failed to read addr 0x%lx, ret %d\n",
                rand_log->buf, ret);
        }

        memcpy(&event_log->event.rand, rand_log, sizeof(rr_random));
        event_log->rip = rip;

        random_cur = NULL;

        if (rr_post_handle_event(vcpu, event_log))
            rr_insert_event_log(event_log);
    }
}

static void handle_event_io_in(struct kvm_vcpu *vcpu, void *opaque)
{
    rr_event_log *event_log;
    unsigned long *io_val = (unsigned long *)opaque;
    rr_io_input *io_input;
    
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    io_input = kmalloc(sizeof(rr_io_input), GFP_KERNEL);

    // printk(KERN_INFO "Recording IO IN: %lx\n", *io_val);

    io_input->value = *io_val;

    event_log->type = EVENT_TYPE_IO_IN;
    event_log->rip = kvm_arch_vcpu_get_ip(vcpu);
    event_log->event.io_input = *io_input;
    event_log->next = NULL;

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);

    // printk(KERN_WARNING "IO event\n");

    return;
}

void handle_hypercall_random(struct kvm_vcpu *vcpu,
                             unsigned long buf,
                             unsigned long len)
{
    rr_event_log *event_log;
    rr_random *rand_log;
    struct x86_emulate_ctxt *emulate_ctxt;
    int ret = 0;

    rand_log = kmalloc(sizeof(rr_random), GFP_KERNEL);

    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    
    event_log->type = EVENT_TYPE_RANDOM;

    rand_log->buf = buf;
    rand_log->len = len;

    emulate_ctxt = vcpu->arch.emulate_ctxt;

    ret = emulate_ctxt->ops->read_emulated(vcpu->arch.emulate_ctxt,
                                        rand_log->buf, rand_log->data, rand_log->len,
                                        &emulate_ctxt->exception);
    if (ret != X86EMUL_CONTINUE) {
        printk(KERN_WARNING "Failed to read addr 0x%lx, ret %d\n",
            rand_log->buf, ret);
    }

    event_log->event.rand = *rand_log;
    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);
}

void handle_hypercall_cfu(struct kvm_vcpu *vcpu,
                          unsigned long src,
                          unsigned long dest,
                          unsigned long len)
{
    rr_event_log *event_log;
    struct x86_emulate_ctxt *emulate_ctxt;
    rr_cfu *cfu_log;
    int ret;

    cfu_log = kmalloc(sizeof(rr_cfu), GFP_KERNEL);

    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);

    cfu_log->src_addr = src;
    cfu_log->dest_addr = dest;
    cfu_log->len = len;

    emulate_ctxt = vcpu->arch.emulate_ctxt;
    event_log->type = EVENT_TYPE_CFU;

    if (cfu_log->len > 4096) {
        printk(KERN_WARNING "Oversized: 0x%lx, %lu\n", dest, len);
    } else {
        // printk(KERN_INFO "Read from src=0x%lx, dest=0x%lx, len=%lu\n", cfu_log->src_addr, cfu_log->dest_addr, cfu_log->len);
        ret = rr_kvm_read_guest_virt(vcpu,
                                    cfu_log->src_addr, cfu_log->data, cfu_log->len,
                                    &emulate_ctxt->exception, PFERR_USER_MASK);
        if (ret != X86EMUL_CONTINUE) {
            printk(KERN_WARNING "Failed to read addr 0x%lx, ret %d\n",
                cfu_log->src_addr, ret);
        }
    }

    event_log->event.cfu = *cfu_log;

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);
}

void handle_hypercall_getuser(struct kvm_vcpu *vcpu,
                              unsigned long val)
{
    rr_event_log *event_log;
    rr_gfu *gfu_log;

    gfu_log = kmalloc(sizeof(rr_gfu), GFP_KERNEL);

    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);

    gfu_log->val = val;
    event_log->type = EVENT_TYPE_GFU;
    event_log->event.gfu = *gfu_log;

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);
}

static void handle_event_rdtsc(struct kvm_vcpu *vcpu, void *opaque)
{
    rr_event_log *event_log;
    unsigned long *tsc_val = (unsigned long *)opaque;
    rr_io_input *io_input;
    
    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);
    io_input = kmalloc(sizeof(rr_io_input), GFP_KERNEL);

    io_input->value = *tsc_val;

    event_log->type = EVENT_TYPE_RDTSC;
    event_log->rip = kvm_arch_vcpu_get_ip(vcpu);
    event_log->event.io_input = *io_input;
    event_log->next = NULL;

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);

    return;
}

static void handle_event_dma_done(struct kvm_vcpu *vcpu, void *opaque)
{
    rr_event_log *event_log;

    event_log = kmalloc(sizeof(rr_event_log), GFP_KERNEL);

    event_log->type = EVENT_TYPE_DMA_DONE;
    event_log->rip = kvm_arch_vcpu_get_ip(vcpu);
    event_log->next = NULL;

    if (rr_post_handle_event(vcpu, event_log))
        rr_insert_event_log(event_log);
    
    // printk(KERN_WARNING "Inserted DMA Done\n");

    return;
}

static void report_record_stat(void)
{
    rr_event_log *event = rr_event_log_head;
    int event_int_num = 0;
    int event_syscall_num = 0;
    int event_pf_excep = 0;
    int event_io_in = 0;
    int event_cfu = 0;
    int event_random = 0;
    int event_dma_done = 0;
    int event_gfu = 0;

    printk(KERN_WARNING "=== Report recorded events ===\n");
    while (event != NULL) {
        if (event->type == EVENT_TYPE_INTERRUPT) {
            event_int_num++;
            // if (event->event.interrupt.lapic.vector == 33)
            //     printk(KERN_INFO "RR Record: INT RIP=%llx", event->rip);
        }

        if (event->type == EVENT_TYPE_SYSCALL) {
            event_syscall_num++;
            // printk(KERN_INFO "RR Record: Syscall Num=%lu", event->event.syscall.regs.rax);
        }

        if (event->type == EVENT_TYPE_EXCEPTION) {
            // printk(KERN_WARNING "except vector=%d error code=%d, addr=%x",
            //        event->event.exception.exception_index,
            //        event->event.exception.error_code,
            //        event->event.exception.cr2);
            event_pf_excep++;
        }

        if (event->type == EVENT_TYPE_IO_IN) {
            event_io_in++;
            // printk(KERN_INFO "RR Record: IO IN=%lx", event->event.io_input.value);
        }

        if (event->type == EVENT_TYPE_RDTSC) {
            event_io_in++;
            // printk(KERN_INFO "RR Record: IO IN=%lx", event->event.io_input.value);
        }

        if (event->type == EVENT_TYPE_CFU) {
            event_cfu++;
            // printk(KERN_INFO "RR Record: CFU rip=0x%lx, addr=0x%lx, inst_cnt=%lu", event->rip, event->event.cfu.dest_addr, event->inst_cnt);
        }

        if (event->type == EVENT_TYPE_GFU) {
            event_gfu++;
            // printk(KERN_INFO "RR Record: DMA Done");
        }

        if (event->type == EVENT_TYPE_RANDOM) {
            event_random++;
            // printk(KERN_INFO "RR Record: Random rip=0x%lx, buf=0x%lx, len=%lu, inst_cnt=%lu",
            //         event->rip, event->event.rand.buf, event->event.rand.len, event->inst_cnt);
        }

        if (event->type == EVENT_TYPE_DMA_DONE) {
            event_dma_done++;
            // printk(KERN_INFO "RR Record: DMA Done");
        }

        total_event_cnt++;

        event = event->next;

    }

    printk(KERN_INFO "syscall=%d, interrupt=%d, pf=%d, io_in=%d, cfu=%d, dma_done=%d, gfu=%d\n",
            event_syscall_num, event_int_num, event_pf_excep, event_io_in, event_cfu, event_dma_done, event_gfu);
}

void rr_set_in_record(struct kvm_vcpu *vcpu, int record)
{
    if (record == in_record) {
        printk(KERN_WARNING "Skip because it's record status is already %d\n", record);
        return;
    }

    in_record = record;

    if (!in_record) {
        report_record_stat();

        kvm_make_request(KVM_REQ_END_RECORD, vcpu);

        rr_event_cur = rr_event_log_head;
        rr_mem_log_cur = rr_mem_log_head;

        vcpu->int_injected = 0;

    } else {
        total_event_cnt = 0;

        printk(KERN_INFO "RR initialized\n");

        kvm_make_request(KVM_REQ_START_RECORD, vcpu);
        vcpu->int_injected = 0;
    }

    rr_clear_mem_log();

}

void clear_events(void)
{
    if (rr_event_log_head != NULL) {
        rr_event_log *pre_event = rr_event_log_head;
        rr_event_log *event;

        while (pre_event != NULL) {
            event = pre_event->next;
            kfree(pre_event);
            pre_event = event;
        }
    }

    rr_event_log_head = NULL;
    rr_event_log_tail = NULL;
    printk(KERN_INFO "Records cleard\n");
}

void rr_clear_mem_log(void)
{
    if (rr_mem_log_head != NULL) {
        // rr_mem_access_log *pre_event = rr_mem_log_head;
        // rr_mem_access_log *event;

        // printk("Freeing mem log\n");

        // while (pre_event != NULL) {
        //     event = pre_event->next;
        //     kfree(pre_event);
        //     pre_event = event;
        //     printk("Free mem log: %p\n", pre_event);
        // }

        rr_mem_log_head = NULL;
        rr_mem_log_tail = NULL;
        rr_mem_log_cur = NULL;
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
EXPORT_SYMBOL_GPL(rr_in_record);

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
    case EVENT_TYPE_IO_IN:
        handle_event_io_in(vcpu, opaque);
        break;
    case EVENT_TYPE_CFU:
        handle_event_cfu(vcpu, opaque);
        break;
    case EVENT_TYPE_RANDOM:
        handle_event_random_generator(vcpu, opaque);
        break;
    case EVENT_TYPE_RDTSC:
        handle_event_rdtsc(vcpu, opaque);
        break;
    case EVENT_TYPE_DMA_DONE:
        handle_event_dma_done(vcpu, opaque);
        break;
    default:
        break;
    }
}
EXPORT_SYMBOL_GPL(rr_record_event);

void rr_trace_memory_write(struct kvm_vcpu *vcpu, gpa_t gpa)
{
    unsigned long rip;
    rr_mem_access_log *log;
    
    rip = kvm_get_linear_rip(vcpu);
    log = kmalloc(sizeof(rr_mem_access_log), GFP_KERNEL);

    log->gpa = gpa;
    log->rip = rip;
    log->inst_cnt = kvm_get_inst_cnt(vcpu) - vcpu->rr_start_point;

    // printk(KERN_INFO "RR record mem access: %lx\n", log->gpa);

    log->next = NULL;

    if (rr_mem_log_tail == NULL) {
        rr_mem_log_head = log;
        rr_mem_log_tail = log;
    } else {
        rr_mem_log_tail->next = log;
        rr_mem_log_tail = rr_mem_log_tail->next;
    }
}

int rr_handle_breakpoint(struct kvm_vcpu *vcpu)
{
    unsigned long addr;

    if (!rr_in_record()) {
        return 0;
    }

    addr = kvm_get_linear_rip(vcpu);

    // printk(KERN_INFO "breakpoint addr 0x%lx\n", addr);

    switch(addr) {
        case syscall_addr:
            rr_record_event(vcpu, EVENT_TYPE_SYSCALL, NULL);
            break;
        case pf_excep_addr:
            rr_record_event(vcpu, EVENT_TYPE_EXCEPTION, new_rr_exception(PF_VECTOR, 0, 0));
            break;
        case copy_from_iter_addr:
        case copy_from_user_addr:
        case strncpy_addr:
        case get_user_addr:
        case strnlen_user_addr:
        case copy_page_from_iter_addr:
            rr_record_event(vcpu, EVENT_TYPE_CFU, &addr);
            break;
        case random_bytes_addr_start:
        case random_bytes_addr_end:
            rr_record_event(vcpu, EVENT_TYPE_RANDOM, NULL);
        default:
            break;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(rr_handle_breakpoint);
