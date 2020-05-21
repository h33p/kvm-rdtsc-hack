#include "kernel-hook/hook.h"
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>

MODULE_DESCRIPTION("Hook and correct KVM TSC timer on X86 platforms. Only one KVM instance is supported.");
MODULE_AUTHOR("Heep");
MODULE_LICENSE("GPL");

static int vmhook_init(void);
static void vmhook_fini(void);

module_init(vmhook_init);
module_exit(vmhook_fini);

#define printkvm(format, ...) printk(KBUILD_MODNAME": "format, ##__VA_ARGS__)

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
		.cpu_id = -1,
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
			.cpu_id = -1,
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

	preempt_disable();

	cur_tsc = rdtsc();
	off_info = get_cpu_offset_info(vcpu);
	off_info->vcpu = vcpu;
	off_info->vmexit_tsc = cur_tsc;
	off_info->cpu_id = smp_processor_id();

	preempt_enable();
}

static void vcpu_pre_run(struct kvm_vcpu *vcpu) {
	u64 cur_tsc, off, tsc_offset, new_tsc_offset;
	s64 tsc_shift_back;
	struct vcpu_offset_info *off_info;

	preempt_disable();

	tsc_offset = kvm_x86_ops->read_l1_tsc_offset(vcpu);
	new_tsc_offset = tsc_offset;
	off_info = get_cpu_offset_info(vcpu);

	if (off_info->cpu_id == smp_processor_id()) {
		if (off_info->called_cpuid) {
			cur_tsc = rdtsc();
			off = -kvm_scale_tsc(vcpu, 1000 + cur_tsc - off_info->vmexit_tsc);
			new_tsc_offset += off;
			off_info->temp_offset += off;
		} else { /* Shift the tsc back if not cpuid exit */
			tsc_shift_back = off_info->temp_offset;
			if (tsc_shift_back < -500)
				tsc_shift_back = -500;
			new_tsc_offset -= tsc_shift_back;
			off_info->temp_offset -= tsc_shift_back;
		}

		if (tsc_offset ^ new_tsc_offset)
			vcpu->arch.tsc_offset = kvm_x86_ops->write_l1_tsc_offset(vcpu, new_tsc_offset);
	}

	off_info->called_cpuid = 0;

	preempt_enable();
}

DEFINE_STATIC_HOOK(int, kvm_emulate_cpuid, struct kvm_vcpu *vcpu)
{
	DEFINE_ORIGINAL(kvm_emulate_cpuid);

	get_cpu_offset_info(vcpu)->called_cpuid = 1;

	return orig_fn(vcpu);
}

DEFINE_STATIC_HOOK(void, kvm_vcpu_run, struct kvm_vcpu *vcpu)
{
	DEFINE_ORIGINAL(kvm_vcpu_run);

	vcpu_pre_run(vcpu);
	orig_fn(vcpu);
	vcpu_post_run(vcpu);
}

static int error_quit(const char *msg)
{
	printkvm("%s\n", msg);
	return -EFAULT;
}

DEFINE_HOOK_GETTER(kvm_vcpu_run)
{
       return (uintptr_t)kvm_x86_ops->run;
}

static const fthinit_t hook_list[] = {
	HLIST_NAME_ENTRY(kvm_emulate_cpuid),
	HLIST_GETTER_ENTRY(kvm_vcpu_run)
};

static int vmhook_init(void)
{
	int ret;

	printkvm("initializing...\n");

	ret = start_hook_list(hook_list, ARRAY_SIZE(hook_list));

	if (ret == -1)
		return error_quit("Last error: Failed to lookup symbols!");
	else if (ret == 1)
		return error_quit("Last error: Failed to call ftrace_set_filter_ip!");
	else if (ret == 2)
		return error_quit("Last error: Failed to call ftrace_set_filter_ip!");

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
