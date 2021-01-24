#include "kernel-hook/hook.h"
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include "kallsyms-mod/kallsyms.c"

MODULE_DESCRIPTION("Hook and correct KVM TSC timer on X86 platforms. Only one KVM instance is supported.");
MODULE_AUTHOR("Heep");
MODULE_LICENSE("GPL");

static int vmhook_init(void);
static void vmhook_fini(void);

module_init(vmhook_init);
module_exit(vmhook_fini);

int constant_tsc_offset = 1000;

module_param(constant_tsc_offset,int,0660);

#define printkvm(format, ...) printk(KBUILD_MODNAME": "format, ##__VA_ARGS__)

int (*kvm_set_tsc_khz)(struct kvm_vcpu *vcpu, u32 user_tsc_khz) = NULL;

//We do not really support multiple KVM instances here
struct vcpu_offset_info {
	struct kvm_vcpu *vcpu;
	int cpu_id;
	int called_cpuid;
	s64 temp_offset;
	u64 vmexit_tsc;
} cpu_offsets[KVM_MAX_VCPUS] = {
	{
		.vcpu = NULL,
		.called_cpuid = 0,
		.temp_offset = 0,
		.vmexit_tsc = 0
	}
};

static struct vcpu_offset_info* get_cpu_offset_info(struct kvm_vcpu *vcpu) {
	struct vcpu_offset_info* ret = cpu_offsets + vcpu->vcpu_idx;

	if (ret->vcpu != vcpu) {
		*ret = (struct vcpu_offset_info) {
			.vcpu = vcpu,
			.called_cpuid = 0,
			.temp_offset = 0,
			.vmexit_tsc = rdtsc()
		};
	}

	return ret;
}

static void vcpu_post_run(struct kvm_vcpu *vcpu) {
	u64 cur_tsc;
	struct vcpu_offset_info *off_info;

	cur_tsc = rdtsc();
	off_info = get_cpu_offset_info(vcpu);
	off_info->vcpu = vcpu;
	off_info->vmexit_tsc = cur_tsc;
}

static void vcpu_pre_run(struct kvm_vcpu *vcpu) {
	u64 cur_tsc, off, tsc_offset, new_tsc_offset;
	s64 tsc_shift_back;
	int called_cpuid;
	struct vcpu_offset_info *off_info;
	int tsc_off = constant_tsc_offset;

	tsc_offset = vcpu->arch.l1_tsc_offset;
	new_tsc_offset = tsc_offset;
	off_info = get_cpu_offset_info(vcpu);

	called_cpuid = off_info->called_cpuid;

	if (called_cpuid) {
			/* Needs to be applied on CPU creation, also, we probably can not scale the TSC down */
			/*if (kvm_set_tsc_khz)
				kvm_set_tsc_khz(vcpu, tsc_khz * 10);*/
			cur_tsc = rdtsc();
			off = -kvm_scale_tsc(vcpu, tsc_off + cur_tsc - off_info->vmexit_tsc);
			new_tsc_offset += off;
			off_info->temp_offset += off;

	} else { /* Shift the tsc back if not cpuid exit */
			tsc_shift_back = off_info->temp_offset;
			if (tsc_shift_back < -tsc_off / 2)
					tsc_shift_back = -tsc_off / 2;
			new_tsc_offset -= tsc_shift_back;
			off_info->temp_offset -= tsc_shift_back;
	}

	if (tsc_offset ^ new_tsc_offset)
			vcpu->arch.tsc_offset = kvm_x86_ops.write_l1_tsc_offset(vcpu, new_tsc_offset);

	off_info->called_cpuid = 0;
}

DEFINE_STATIC_FUNCTION_HOOK(int, kvm_emulate_cpuid, struct kvm_vcpu *vcpu)
{
	DEFINE_ORIGINAL(kvm_emulate_cpuid);

	if (vcpu->arch.regs[VCPU_REGS_RAX] == 0)
		get_cpu_offset_info(vcpu)->called_cpuid = 1;

	return orig_fn(vcpu);
}

DEFINE_STATIC_FUNCTION_HOOK(void, kvm_load_host_xsave_state, struct kvm_vcpu *vcpu)
{
	DEFINE_ORIGINAL(kvm_load_host_xsave_state);

	vcpu_post_run(vcpu);
	/*preempt_enable();
	local_irq_enable();*/

	orig_fn(vcpu);
}

DEFINE_STATIC_FUNCTION_HOOK(void, kvm_load_guest_xsave_state, struct kvm_vcpu *vcpu)
{
	DEFINE_ORIGINAL(kvm_load_guest_xsave_state);

	orig_fn(vcpu);

	/*local_irq_disable();
	preempt_disable();*/
	vcpu_pre_run(vcpu);
}

int callcount = 0;

static int error_quit(const char *msg)
{
	printkvm("%s\n", msg);
	return -EFAULT;
}

static const fthinit_t hook_list[] = {
	HLIST_NAME_ENTRY(kvm_emulate_cpuid),
	HLIST_NAME_ENTRY(kvm_load_host_xsave_state),
	HLIST_NAME_ENTRY(kvm_load_guest_xsave_state)
};

static int vmhook_init(void)
{
	int ret;

	printkvm("initializing...\n");

	if ((ret = init_kallsyms()))
		return ret;

	kvm_set_tsc_khz = (typeof(kvm_set_tsc_khz))kallsyms_lookup_name("kvm_set_tsc_khz");

	ret = start_hook_list(hook_list, ARRAY_SIZE(hook_list));

	if (ret == -1)
		return error_quit("Last error: Failed to lookup symbols!");
	else if (ret == 1)
		return error_quit("Last error: Failed to call ftrace_set_filter_ip! (1)");
	else if (ret == 2)
		return error_quit("Last error: Failed to call ftrace_set_filter_ip! (2)");

	printkvm("KVMHook initialized!\n");

	return 0;
}

static void vmhook_fini(void)
{
	int ret;
	printkvm("unloading...\n");

	ret = end_hook_list(hook_list, ARRAY_SIZE(hook_list));

	if (ret) {
		error_quit("Failed to unregister the ftrace function");
		return;
	}

	printkvm("KVMHook unloaded!\n");
}
