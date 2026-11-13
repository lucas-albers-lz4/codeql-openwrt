/*
 * Isolated double of HTTP /ubus luci.getOdhcp6cStats:
 *   uhttpd parse_call_params + uh_ubus_allowed (session.access
 *   scope=ubus object=luci function=getOdhcp6cStats; uhttpd omits scope)
 *
 * Bounded to luci-mod-status-index 30_network.js rpc.declare
 * object=luci method=getOdhcp6cStats at luci b2e0be4b. Does not invoke
 * the luci-base getOdhcp6cStats handler (network.device status / odhcp6c.<dev> get_statistics). Does not staff
 * getVersion, getUnixtime, system.board, or system.info. No live
 * ubus/rpcd/luci plugin.
 *
 * Build:
 *   gcc -std=c11 -Wall -Wextra -Werror -O0 -o ubus_luci_getodhcp6cstats ubus_luci_getodhcp6cstats.c
 *
 * Pins: uhttpd 93b05e0b65d91c23c5aa8fdde378df1f174ec71d
 *       rpcd   d99f703e4035d03fbcfbada3cb697db346c2b984
 */

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UBUS_OBJECT "luci"
#define UBUS_METHOD "getOdhcp6cStats"
#define UHTTPD_SHA "93b05e0b65d91c23c5aa8fdde378df1f174ec71d"
#define RPCD_SHA "d99f703e4035d03fbcfbada3cb697db346c2b984"

static const char *arg_or_null(const char *s)
{
	if (s == NULL || strcmp(s, "-") == 0)
		return NULL;
	return s;
}

static int data_is_table(const char *s)
{
	return s != NULL && (strcmp(s, "1") == 0 || strcmp(s, "table") == 0 ||
			     strcmp(s, "{}") == 0);
}

static int data_missing(const char *s)
{
	return s == NULL || strcmp(s, "0") == 0 || strcmp(s, "-") == 0;
}

static int uh_id_len(const char *str)
{
	return (int)strcspn(str, "*?[");
}

static int acl_match(const char *pat_obj, const char *pat_fun,
		     const char *obj, const char *fun)
{
	int sort_len = uh_id_len(pat_obj);

	if (strncmp(pat_obj, obj, (size_t)sort_len) != 0)
		return 0;
	if (fnmatch(pat_obj, obj, FNM_NOESCAPE) != 0)
		return 0;
	if (fnmatch(pat_fun, fun, FNM_NOESCAPE) != 0)
		return 0;
	return 1;
}

static int cmd_parse(int argc, char **argv)
{
	const char *sid, *object, *function, *data;

	if (argc != 4) {
		fprintf(stderr, "parse: expected 4 args\n");
		return 2;
	}
	sid = arg_or_null(argv[0]);
	object = arg_or_null(argv[1]);
	function = arg_or_null(argv[2]);
	data = arg_or_null(argv[3]);
	if (sid == NULL || object == NULL || function == NULL ||
	    data_missing(data) || !data_is_table(data)) {
		puts("ERROR_PARSE");
		return 1;
	}
	puts("PARSE_OK");
	return 0;
}

static int cmd_match(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "match: expected 4 args\n");
		return 2;
	}
	if (acl_match(argv[0], argv[1], argv[2], argv[3])) {
		puts("ALLOW");
		return 0;
	}
	puts("DENY");
	return 1;
}

static int cmd_decide(int argc, char **argv)
{
	const char *sid, *object, *function, *data;
	const char *obj_pat, *fun_pat;

	if (argc != 6) {
		fprintf(stderr, "decide: expected 6 args\n");
		return 2;
	}

	sid = arg_or_null(argv[0]);
	object = arg_or_null(argv[1]);
	function = arg_or_null(argv[2]);
	data = arg_or_null(argv[3]);
	obj_pat = arg_or_null(argv[4]);
	fun_pat = arg_or_null(argv[5]);

	if (sid == NULL || object == NULL || function == NULL ||
	    data_missing(data) || !data_is_table(data)) {
		puts("ERROR_PARSE");
		return 1;
	}

	if (strcmp(object, UBUS_OBJECT) != 0 ||
	    strcmp(function, UBUS_METHOD) != 0) {
		puts("NOT_THIS_SLICE");
		return 1;
	}

	if (!(obj_pat && fun_pat &&
	      acl_match(obj_pat, fun_pat, UBUS_OBJECT, UBUS_METHOD))) {
		puts("ERROR_ACCESS");
		return 1;
	}

	puts("ALLOW");
	return 0;
}

static int cmd_flags(void)
{
	printf("UHTTPD_SHA=%s\n", UHTTPD_SHA);
	printf("RPCD_SHA=%s\n", RPCD_SHA);
	printf("UBUS_OBJECT=%s\n", UBUS_OBJECT);
	printf("UBUS_METHOD=%s\n", UBUS_METHOD);
	printf("FNM_NOESCAPE=%d\n", FNM_NOESCAPE);
	return 0;
}

static void usage(FILE *fp)
{
	fprintf(fp,
		"usage: ubus_luci_getodhcp6cstats parse <sid|-> <object|-> <function|-> <data|->\n"
		"       ubus_luci_getodhcp6cstats match <obj_pat> <fun_pat> <object> <function>\n"
		"       ubus_luci_getodhcp6cstats decide <sid|-> <object|-> <function|-> <data|-> <obj_pat|-> <fun_pat|->\n"
		"       ubus_luci_getodhcp6cstats flags\n");
}

int main(int argc, char **argv)
{
	const char *cmd;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}

	cmd = argv[1];
	if (strcmp(cmd, "parse") == 0)
		return cmd_parse(argc - 2, argv + 2);
	if (strcmp(cmd, "match") == 0)
		return cmd_match(argc - 2, argv + 2);
	if (strcmp(cmd, "decide") == 0)
		return cmd_decide(argc - 2, argv + 2);
	if (strcmp(cmd, "flags") == 0)
		return cmd_flags();

	usage(stderr);
	return 2;
}
