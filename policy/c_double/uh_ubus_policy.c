/*
 * Isolated double of:
 *   uhttpd ubus.c parse_call_params + the call-method parse/auth gate
 *   uhttpd ubus.c conf.ubus_noauth skip of uh_ubus_allowed
 *   rpcd session.c rpc_session_acl_allowed / rpc_login_test_permission
 *
 * No live ubus/uhttpd/rpcd. Literal object/method names plus libc fnmatch.
 *
 * Build (record these flags in policy_decisions.json harness):
 *   gcc -std=c11 -Wall -Wextra -Werror -O0 -o uh_ubus_policy uh_ubus_policy.c
 *
 * Pins: uhttpd 93b05e0b65d91c23c5aa8fdde378df1f174ec71d
 *       rpcd   d99f703e4035d03fbcfbada3cb697db346c2b984
 */

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UH_UBUS_DEFAULT_SID "00000000000000000000000000000000"

static const char *arg_or_null(const char *s)
{
	if (s == NULL || strcmp(s, "-") == 0)
		return NULL;
	return s;
}

/* uhttpd parse_call_params: fourth parameter must be BLOBMSG_TYPE_TABLE. */
static int data_is_table(const char *s)
{
	return s != NULL && (strcmp(s, "1") == 0 || strcmp(s, "table") == 0 ||
			     strcmp(s, "{}") == 0);
}

static int data_missing(const char *s)
{
	return s == NULL || strcmp(s, "0") == 0 || strcmp(s, "-") == 0;
}

/* rpcd session.c uh_id_len */
static int uh_id_len(const char *str)
{
	return (int)strcspn(str, "*?[");
}

/*
 * rpcd session.c uh_foreach_matching_acl / rpc_session_acl_allowed
 * for a single (object, function) ACL entry.
 */
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

/* libubox blobmsg_parse_array advances only when a type matches. */
static int parse_args(int noauth, const char *in_sid, const char *in_object,
                      const char *in_function, const char *in_data,
                      const char **sid, const char **object, const char **function,
                      int *rewritten)
{
    const char *in[] = {arg_or_null(in_sid), arg_or_null(in_object),
                        arg_or_null(in_function), in_data};
    const char *out[] = {NULL, NULL, NULL, NULL};
    int index = 0;
    for (int i = 0; i < 4 && index < 4; i++) {
        /* Angle-bracket tokens are test-double representations of nonstrings. */
        int is_string = i < 3 ? in[i] && strcmp(in[i], "<number>") &&
            strcmp(in[i], "<array>") && strcmp(in[i], "<bool>") &&
            strcmp(in[i], "<table>") : strcmp(in[i], "string") == 0;
        int is_table = i == 3 && !data_missing(in[i]) && data_is_table(in[i]);
        if ((index < 3 && is_string) || (index == 3 && is_table))
            out[index++] = in[i];
    }
    *sid = out[0]; *object = out[1]; *function = out[2]; *rewritten = 0;
    if (noauth && (!*sid || !**sid)) {
        *sid = UH_UBUS_DEFAULT_SID;
        *rewritten = 1;
    }
    return *sid && *object && *function && out[3];
}

static int cmd_parse(int argc, char **argv)
{
    const char *sid, *object, *function;
    int rewritten;
    if (argc != 5) {
        fprintf(stderr, "parse: expected 5 args\n");
        return 2;
    }
    if (!parse_args(atoi(argv[0]), argv[1], argv[2], argv[3], argv[4],
                    &sid, &object, &function, &rewritten)) {
        puts("ERROR_PARSE");
        return 1;
    }
    printf("OK sid=%s object=%s function=%s rewritten=%d\n",
           sid, object, function, rewritten);
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

/* rpcd session.c rpc_login_test_permission positive fnmatch(pat, group, 0) */
static int cmd_group(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "group: expected 2 args\n");
		return 2;
	}

	if (fnmatch(argv[0], argv[1], 0) == 0) {
		puts("MATCH");
		return 0;
	}
	puts("NO_MATCH");
	return 1;
}

static int cmd_decide(int argc, char **argv)
{
    const char *sid, *object, *function;
    int no_ubusauth, rewritten;
    if (argc != 7 && argc != 8) {
        fprintf(stderr, "decide: expected 7 or 8 args\n");
        return 2;
    }
    no_ubusauth = atoi(argv[0]);
    if (!parse_args(no_ubusauth, argv[1], argv[2], argv[3], argv[4],
                    &sid, &object, &function, &rewritten)) {
        puts("ERROR_PARSE");
        return 1;
    }
    /* Object lookup precedes the authorization gate. */
    if (argc == 8 && !atoi(argv[7])) {
        puts("ERROR_OBJECT");
        return 1;
    }
    if (no_ubusauth || acl_match(argv[5], argv[6], object, function)) {
        puts("ALLOW");
        return 0;
    }
    puts("DENY");
    return 1;
}

static int cmd_flags(void)
{
	printf("FNM_NOESCAPE=%d\n", FNM_NOESCAPE);
	printf("UH_UBUS_DEFAULT_SID=%s\n", UH_UBUS_DEFAULT_SID);
	return 0;
}

static void usage(FILE *fp)
{
	fprintf(fp,
		"usage: uh_ubus_policy parse <no_ubusauth> <sid|-> <object|-> <function|-> <data 0|1|table|array|string|number|bool>\n"
		"       uh_ubus_policy match <obj_pat> <fun_pat> <object> <function>\n"
		"       uh_ubus_policy group <login_pat> <acl_group>\n"
		"       uh_ubus_policy decide <no_ubusauth> <sid|-> <object|-> <function|-> <data 0|1|table|array|string|number|bool> <obj_pat> <fun_pat> [object_exists 0|1]\n"
		"       uh_ubus_policy flags\n");
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
	if (strcmp(cmd, "group") == 0)
		return cmd_group(argc - 2, argv + 2);
	if (strcmp(cmd, "decide") == 0)
		return cmd_decide(argc - 2, argv + 2);
	if (strcmp(cmd, "flags") == 0)
		return cmd_flags();

	usage(stderr);
	return 2;
}
