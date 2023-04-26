#include <linux/kvm_host.h>
#include <asm/kernel_rr.h>

void rr_record_event(struct kvm_vcpu *vcpu, int event_type, void *opaque);
lapic_log* create_lapic_log(int delivery_mode, int vector, int trig_mode);
int rr_in_record(void);
int rr_in_replay(void);
void rr_set_in_record(struct kvm_vcpu *vcpu, int record);
void rr_set_in_replay(struct kvm_vcpu *vcpu, int replay);
void rr_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs);
void rr_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs);

unsigned long get_rsi(struct kvm_vcpu *vcpu);

int rr_handle_breakpoint(struct kvm_vcpu *vcpu);

int rr_do_singlestep(struct kvm_vcpu *vcpu);
void rr_update_apicv_inhibit(struct kvm *kvm);

void rr_set_reg(struct kvm_vcpu *vcpu, int index, unsigned long val);

void kvm_start_inst_cnt(struct kvm_vcpu *vcpu);
void kvm_stop_inst_cnt(struct kvm_vcpu *vcpu);
u64 kvm_get_inst_cnt(struct kvm_vcpu *vcpu);

int rr_get_event_list_length(void);
void rr_copy_to_event_list(struct rr_event_list_t *event_list, int len);
rr_event_log rr_get_next_event(void);


