/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace loader for scx_cala.
 */
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <scx/common.h>

#include "scx_cala.bpf.skel.h"

static const char help_fmt[] =
"A cache-affinity and load-aware sched_ext scheduler.\n"
"\n"
"This initial scaffold does not yet implement project scheduling modes.\n"
"\n"
"Usage: %s [-vh]\n"
"\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile sig_atomic_t exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			  va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void signal_handler(int signo)
{
	(void)signo;
	exit_req = 1;
}

static int parse_options(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "vh")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'h':
			fprintf(stdout, help_fmt, basename(argv[0]));
			return 1;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return -1;
		}
	}

	return 0;
}

static void print_stats(const struct scx_cala *skel, int nr_cpus)
{
	__u64 executions[nr_cpus];
	__u32 zero = 0;
	int cpu;

	memset(executions, 0, sizeof(executions));
	if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.actual_executions),
				&zero, executions))
		memset(executions, 0, sizeof(executions));

	printf("runnable=%llu runnable_events=%llu quiescent_events=%llu "
	       "running_events=%llu selection_matches=%llu "
	       "selection_mismatches=%llu runnable_without_select=%llu "
	       "selection_not_observed=%llu "
	       "duplicate_runnable=%llu unmatched_quiescent=%llu "
	       "task_storage_failures=%llu stats_map_failures=%llu",
	       (unsigned long long)skel->bss->nr_runnable,
	       (unsigned long long)skel->bss->nr_runnable_events,
	       (unsigned long long)skel->bss->nr_quiescent_events,
	       (unsigned long long)skel->bss->nr_running_events,
	       (unsigned long long)skel->bss->nr_selection_matches,
	       (unsigned long long)skel->bss->nr_selection_mismatches,
	       (unsigned long long)skel->bss->nr_runnable_without_select,
	       (unsigned long long)skel->bss->nr_selection_not_observed,
	       (unsigned long long)skel->bss->nr_duplicate_runnable,
	       (unsigned long long)skel->bss->nr_unmatched_quiescent,
	       (unsigned long long)skel->bss->nr_task_storage_failures,
	       (unsigned long long)skel->bss->nr_stats_map_failures);
	for (cpu = 0; cpu < nr_cpus; cpu++)
		printf(" executions_cpu%d=%llu", cpu,
		       (unsigned long long)executions[cpu]);
	putchar('\n');
	fflush(stdout);
}

int main(int argc, char **argv)
{
	struct scx_cala *skel;
	struct bpf_link *link;
	__u64 ecode;
	int nr_cpus, ret;

	ret = parse_options(argc, argv);
	if (ret)
		return ret < 0;

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 1) {
		fprintf(stderr, "Failed to determine the number of possible CPUs\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

restart:
	skel = SCX_OPS_OPEN(cala_ops, scx_cala);
	SCX_OPS_LOAD(skel, cala_ops, scx_cala, uei);
	link = SCX_OPS_ATTACH(skel, cala_ops, scx_cala);

	printf("scx_cala is running. Press Ctrl-C to exit.\n");
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		print_stats(skel, nr_cpus);
		sleep(1);
	}
	print_stats(skel, nr_cpus);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_cala__destroy(skel);

	if (!exit_req && UEI_ECODE_RESTART(ecode))
		goto restart;

	return 0;
}
