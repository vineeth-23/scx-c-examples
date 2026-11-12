/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cala: cache-affinity and load-aware sched_ext scheduler.
 *
 * This initial scaffold uses the kernel's default CPU selection helper and
 * the built-in global FIFO dispatch queue. Project-specific placement and
 * accounting policies are intentionally not implemented in this phase.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS(cala_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

void BPF_STRUCT_OPS(cala_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(cala_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cala_ops,
	       .select_cpu		= (void *)cala_select_cpu,
	       .enqueue			= (void *)cala_enqueue,
	       .exit			= (void *)cala_exit,
	       .name			= "cala");
