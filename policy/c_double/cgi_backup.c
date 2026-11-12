/*
 * Isolated double of cgi-io main_backup @ 31cb3c89f02d918d7f17bf62a80c852fc38a1ca1:
 *   Inputs are already-decoded form fields. Successful CONTENT_LENGTH/body
 *   framing and URL decoding are preconditions; those postdecode failures are
 *   not modeled by this authorization double.
 *   postdecode sessionid (application/x-www-form-urlencoded)
 *   session_access(sid, "cgi-io", "backup", "read")
 *
 * Does not fork /sbin/sysupgrade --create-backup. No live ubus/cgi-io.
 * Does not model cgi-upload, cgi-download, or cgi-exec.
 *
 * Build (record these flags in cgi_backup_decisions.json harness):
 *   gcc -std=c11 -Wall -Wextra -Werror -O0 -o cgi_backup cgi_backup.c
 *
 * Pins: cgi-io 31cb3c89f02d918d7f17bf62a80c852fc38a1ca1
 *       rpcd   d99f703e4035d03fbcfbada3cb697db346c2b984
 */

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CT_PREFIX "application/x-www-form-urlencoded"
#define CT_PREFIX_LEN 33
#define REQ_SCOPE "cgi-io"
#define REQ_OBJECT "backup"
#define REQ_FUNCTION "read"
#define CGI_IO_SHA "31cb3c89f02d918d7f17bf62a80c852fc38a1ca1"

static const char *arg_or_null(const char *s)
{
	if (s == NULL || strcmp(s, "-") == 0)
		return NULL;
	return s;
}

/* rpcd session.c uh_id_len */
static int uh_id_len(const char *str)
{
	return (int)strcspn(str, "*?[");
}

/*
 * rpcd session.c uh_foreach_matching_acl / rpc_session_acl_allowed
 * for a single (object, function) ACL entry after an exact scope match.
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

static int scope_match(const char *pat_scope, const char *scope)
{
	return strcmp(pat_scope, scope) == 0;
}

/* cgi-io util.c postdecode CONTENT_TYPE prefix check, given successfully
 * framed and URL-decoded form input (the body parser is outside this double).
 */
static int content_type_ok(const char *ct)
{
	return ct != NULL && strncmp(ct, CT_PREFIX, CT_PREFIX_LEN) == 0;
}

static int gate_parse(const char *content_type, const char *sid)
{
	if (!content_type_ok(content_type)) {
		puts("HTTP_400");
		return 1;
	}
	if (sid == NULL || sid[0] == '\0') {
		puts("HTTP_403");
		return 1;
	}
	return 0;
}

static int cmd_parse(int argc, char **argv)
{
	const char *content_type, *sid;

	if (argc != 2) {
		fprintf(stderr, "parse: expected 2 args\n");
		return 2;
	}

	content_type = arg_or_null(argv[0]);
	sid = arg_or_null(argv[1]);
	if (gate_parse(content_type, sid) != 0)
		return 1;
	puts("PARSE_OK");
	return 0;
}

static int cmd_match(int argc, char **argv)
{
	if (argc != 6) {
		fprintf(stderr, "match: expected 6 args\n");
		return 2;
	}

	if (scope_match(argv[0], argv[3]) &&
	    acl_match(argv[1], argv[2], argv[4], argv[5])) {
		puts("ALLOW");
		return 0;
	}
	puts("DENY");
	return 1;
}

static int cmd_decide(int argc, char **argv)
{
	const char *content_type, *sid, *pat_scope, *pat_obj, *pat_fun;

	if (argc != 5) {
		fprintf(stderr, "decide: expected 5 args\n");
		return 2;
	}

	content_type = arg_or_null(argv[0]);
	sid = arg_or_null(argv[1]);
	pat_scope = argv[2];
	pat_obj = argv[3];
	pat_fun = argv[4];

	if (gate_parse(content_type, sid) != 0)
		return 1;

	if (scope_match(pat_scope, REQ_SCOPE) &&
	    acl_match(pat_obj, pat_fun, REQ_OBJECT, REQ_FUNCTION)) {
		puts("ALLOW");
		return 0;
	}
	puts("HTTP_403");
	return 1;
}

static int cmd_flags(void)
{
	printf("CGI_IO_SHA=%s\n", CGI_IO_SHA);
	printf("CT_PREFIX=%s\n", CT_PREFIX);
	printf("REQ_SCOPE=%s\n", REQ_SCOPE);
	printf("REQ_OBJECT=%s\n", REQ_OBJECT);
	printf("REQ_FUNCTION=%s\n", REQ_FUNCTION);
	printf("FNM_NOESCAPE=%d\n", FNM_NOESCAPE);
	return 0;
}

static void usage(FILE *fp)
{
	fprintf(fp,
		"usage: cgi_backup parse <content_type|-> <sessionid|->\n"
		"       cgi_backup match <scope_pat> <obj_pat> <fun_pat> <scope> <object> <function>\n"
		"       cgi_backup decide <content_type|-> <sessionid|-> <scope_pat> <obj_pat> <fun_pat>\n"
		"       cgi_backup flags\n");
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
