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

struct task_ctx {
	bool runnable;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

u64 nr_runnable;
u64 nr_runnable_events;
u64 nr_quiescent_events;
u64 nr_duplicate_runnable;
u64 nr_unmatched_quiescent;
u64 nr_task_storage_failures;

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		__sync_fetch_and_add(&nr_task_storage_failures, 1);
		scx_bpf_error("task context lookup failed");
	}

	return tctx;
}

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

s32 BPF_STRUCT_OPS(cala_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	(void)args;
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (tctx)
		return 0;

	__sync_fetch_and_add(&nr_task_storage_failures, 1);
	return -ENOMEM;
}

void BPF_STRUCT_OPS(cala_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	(void)enq_flags;
	__sync_fetch_and_add(&nr_runnable_events, 1);

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->runnable) {
		__sync_fetch_and_add(&nr_duplicate_runnable, 1);
		return;
	}

	tctx->runnable = true;
	__sync_fetch_and_add(&nr_runnable, 1);
}

void BPF_STRUCT_OPS(cala_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;
	u64 old_count;

	(void)deq_flags;
	__sync_fetch_and_add(&nr_quiescent_events, 1);

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	if (!tctx->runnable) {
		__sync_fetch_and_add(&nr_unmatched_quiescent, 1);
		return;
	}

	tctx->runnable = false;
	old_count = __sync_fetch_and_sub(&nr_runnable, 1);
	if (!old_count) {
		__sync_fetch_and_add(&nr_runnable, 1);
		__sync_fetch_and_add(&nr_unmatched_quiescent, 1);
	}
}

void BPF_STRUCT_OPS(cala_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cala_ops,
	       .select_cpu		= (void *)cala_select_cpu,
	       .enqueue			= (void *)cala_enqueue,
	       .runnable		= (void *)cala_runnable,
	       .quiescent		= (void *)cala_quiescent,
	       .init_task		= (void *)cala_init_task,
	       .exit			= (void *)cala_exit,
	       .name			= "cala");
