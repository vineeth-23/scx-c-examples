/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace loader for scx_cala.
 */
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
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

int main(int argc, char **argv)
{
	struct scx_cala *skel;
	struct bpf_link *link;
	__u64 ecode;
	int ret;

	ret = parse_options(argc, argv);
	if (ret)
		return ret < 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

restart:
	skel = SCX_OPS_OPEN(cala_ops, scx_cala);
	SCX_OPS_LOAD(skel, cala_ops, scx_cala, uei);
	link = SCX_OPS_ATTACH(skel, cala_ops, scx_cala);

	printf("scx_cala is running. Press Ctrl-C to exit.\n");
	while (!exit_req && !UEI_EXITED(skel, uei))
		sleep(1);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_cala__destroy(skel);

	if (!exit_req && UEI_ECODE_RESTART(ecode))
		goto restart;

	return 0;
}
