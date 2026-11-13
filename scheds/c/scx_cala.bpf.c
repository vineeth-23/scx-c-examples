/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cala: cache-affinity and load-aware sched_ext scheduler.
 *
 * This implementation currently uses the kernel's default CPU selection
 * helper and the built-in global FIFO dispatch queue. The load-only policy
 * target is computed for observation, but does not influence placement yet.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile u32 nr_cpu_ids = 1;

struct task_ctx {
	bool runnable;
	bool selection_pending;
	bool load_policy_pending;
	s32 selected_cpu;
	s32 load_policy_cpu;
	s32 assigned_cpu;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1);
} actual_executions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(s64));
	__uint(max_entries, 1);
} cpu_runnable SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1);
} load_policy_selections SEC(".maps");

u64 nr_runnable;
u64 nr_runnable_events;
u64 nr_quiescent_events;
u64 nr_running_events;
u64 nr_selection_matches;
u64 nr_selection_mismatches;
u64 nr_runnable_without_select;
u64 nr_selection_not_observed;
u64 nr_duplicate_runnable;
u64 nr_unmatched_quiescent;
u64 nr_task_storage_failures;
u64 nr_stats_map_failures;
u64 nr_assignment_repairs;
u64 nr_invalid_cpus;
u64 nr_cpu_load_lookup_failures;
u64 nr_cpu_load_underflows;
u64 nr_load_policy_evaluations;
u64 nr_load_policy_ties;
u64 nr_load_policy_no_candidate;
u64 nr_load_policy_matches_default;
u64 nr_load_policy_differs_default;
u64 nr_load_policy_matches_actual;
u64 nr_load_policy_differs_actual;
u64 nr_load_policy_not_observed;
u64 nr_load_policy_invalid_target;
u64 nr_load_policy_selection_map_failures;
u32 load_tie_cursor;

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

static s64 *lookup_cpu_load(s32 cpu)
{
	u32 key;
	s64 *load;

	if (cpu < 0 || (u32)cpu >= nr_cpu_ids) {
		__sync_fetch_and_add(&nr_invalid_cpus, 1);
		scx_bpf_error("invalid CPU %d for runnable accounting", cpu);
		return NULL;
	}

	key = cpu;
	load = bpf_map_lookup_elem(&cpu_runnable, &key);
	if (!load) {
		__sync_fetch_and_add(&nr_cpu_load_lookup_failures, 1);
		scx_bpf_error("CPU %d runnable counter lookup failed", cpu);
	}

	return load;
}

static bool increment_cpu_load(s32 cpu)
{
	s64 *load = lookup_cpu_load(cpu);

	if (!load)
		return false;

	__sync_fetch_and_add(load, 1);
	return true;
}

static bool decrement_cpu_load(s32 cpu)
{
	s64 *load = lookup_cpu_load(cpu);
	s64 old_load;

	if (!load)
		return false;

	old_load = __sync_fetch_and_sub(load, 1);
	if (old_load <= 0) {
		__sync_fetch_and_add(load, 1);
		__sync_fetch_and_add(&nr_cpu_load_underflows, 1);
		scx_bpf_error("CPU %d runnable counter underflow", cpu);
		return false;
	}

	return true;
}

/*
 * Compute the load-only policy target without changing actual placement.
 * Starting each scan at a rotating cursor makes the first CPU encountered
 * among equally loaded candidates rotate instead of favoring a low CPU ID.
 */
static s32 load_policy_target(struct task_struct *p)
{
	const struct cpumask *online;
	u64 *selections;
	s64 best_load = 0;
	u32 key, start;
	s32 best_cpu = -1;
	s32 offset;
	bool minimum_tied = false;

	__sync_fetch_and_add(&nr_load_policy_evaluations, 1);
	start = __sync_fetch_and_add(&load_tie_cursor, 1) % nr_cpu_ids;
	online = scx_bpf_get_online_cpumask();

	bpf_for(offset, 0, nr_cpu_ids) {
		s64 *load;
		s32 cpu = (start + offset) % nr_cpu_ids;

		if (!bpf_cpumask_test_cpu(cpu, online) ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		load = lookup_cpu_load(cpu);
		if (!load)
			continue;

		if (best_cpu < 0 || *load < best_load) {
			best_cpu = cpu;
			best_load = *load;
			minimum_tied = false;
		} else if (*load == best_load) {
			minimum_tied = true;
		}
	}

	if (best_cpu < 0) {
		scx_bpf_put_cpumask(online);
		__sync_fetch_and_add(&nr_load_policy_no_candidate, 1);
		return -1;
	}
	if (!bpf_cpumask_test_cpu(best_cpu, online) ||
	    !bpf_cpumask_test_cpu(best_cpu, p->cpus_ptr)) {
		scx_bpf_put_cpumask(online);
		__sync_fetch_and_add(&nr_load_policy_invalid_target, 1);
		return -1;
	}
	scx_bpf_put_cpumask(online);

	if (minimum_tied)
		__sync_fetch_and_add(&nr_load_policy_ties, 1);
	key = best_cpu;
	selections = bpf_map_lookup_elem(&load_policy_selections, &key);
	if (selections)
		__sync_fetch_and_add(selections, 1);
	else
		__sync_fetch_and_add(&nr_load_policy_selection_map_failures, 1);

	return best_cpu;
}

s32 BPF_STRUCT_OPS(cala_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx;
	bool is_idle = false;
	s32 cpu, policy_cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	policy_cpu = load_policy_target(p);
	tctx = lookup_task_ctx(p);
	if (tctx) {
		tctx->selected_cpu = cpu;
		tctx->selection_pending = true;
		tctx->load_policy_cpu = policy_cpu;
		tctx->load_policy_pending = policy_cpu >= 0;
		if (policy_cpu >= 0) {
			if (policy_cpu == cpu)
				__sync_fetch_and_add(&nr_load_policy_matches_default, 1);
			else
				__sync_fetch_and_add(&nr_load_policy_differs_default, 1);
		}
	}

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
	if (tctx) {
		tctx->selected_cpu = -1;
		tctx->load_policy_cpu = -1;
		tctx->assigned_cpu = -1;
		return 0;
	}

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

	if (!tctx->selection_pending) {
		tctx->selected_cpu = scx_bpf_task_cpu(p);
		tctx->selection_pending = true;
		tctx->load_policy_pending = false;
		tctx->load_policy_cpu = -1;
		__sync_fetch_and_add(&nr_runnable_without_select, 1);
	}

	if (!increment_cpu_load(tctx->selected_cpu))
		return;

	tctx->assigned_cpu = tctx->selected_cpu;
	tctx->runnable = true;
	__sync_fetch_and_add(&nr_runnable, 1);
}

void BPF_STRUCT_OPS(cala_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	u32 zero = 0;
	u64 *executions;
	s32 actual_cpu;

	__sync_fetch_and_add(&nr_running_events, 1);
	actual_cpu = scx_bpf_task_cpu(p);

	executions = bpf_map_lookup_elem(&actual_executions, &zero);
	if (executions)
		(*executions)++;
	else
		__sync_fetch_and_add(&nr_stats_map_failures, 1);

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->selection_pending) {
		if (tctx->selected_cpu == actual_cpu)
			__sync_fetch_and_add(&nr_selection_matches, 1);
		else
			__sync_fetch_and_add(&nr_selection_mismatches, 1);

		tctx->selection_pending = false;
	}
	if (tctx->load_policy_pending) {
		if (tctx->load_policy_cpu == actual_cpu)
			__sync_fetch_and_add(&nr_load_policy_matches_actual, 1);
		else
			__sync_fetch_and_add(&nr_load_policy_differs_actual, 1);

		tctx->load_policy_pending = false;
	}

	if (tctx->runnable && tctx->assigned_cpu != actual_cpu) {
		if (!increment_cpu_load(actual_cpu))
			return;
		if (!decrement_cpu_load(tctx->assigned_cpu)) {
			decrement_cpu_load(actual_cpu);
			return;
		}

		tctx->assigned_cpu = actual_cpu;
		__sync_fetch_and_add(&nr_assignment_repairs, 1);
	}
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

	if (tctx->selection_pending)
		__sync_fetch_and_add(&nr_selection_not_observed, 1);
	if (tctx->load_policy_pending)
		__sync_fetch_and_add(&nr_load_policy_not_observed, 1);
	if (!decrement_cpu_load(tctx->assigned_cpu))
		return;

	tctx->selection_pending = false;
	tctx->load_policy_pending = false;
	tctx->selected_cpu = -1;
	tctx->load_policy_cpu = -1;
	tctx->assigned_cpu = -1;
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
	       .running			= (void *)cala_running,
	       .quiescent		= (void *)cala_quiescent,
	       .init_task		= (void *)cala_init_task,
	       .exit			= (void *)cala_exit,
	       .name			= "cala");
