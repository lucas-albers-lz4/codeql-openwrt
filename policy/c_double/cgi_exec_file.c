/*
 * Isolated double of cgi-io main_exec file.exec @ 31cb3c89:
 *   Already-decoded form fields. CONTENT_LENGTH/body/URL-decoding
 *   failures are preconditions, not modeled.
 *   postdecode sessionid (application/x-www-form-urlencoded)
 *   session_access(sid, "cgi-io", "exec", "read")
 *   parse_command / canonicalize_path of argv0
 *   session_access(sid, "file", cmdline, "exec") or
 *   session_access(sid, "file", exe, "exec")
 *
 * Bounded to the three luci-ssl libexec helpers. lookup_executable is
 * not a live PATH/stat search. Does not fork execv. No live ubus/cgi-io.
 *
 * Build:
 *   gcc -std=c11 -Wall -Wextra -Werror -O0 -o cgi_exec_file cgi_exec_file.c
 *
 * Pins: cgi-io 31cb3c89f02d918d7f17bf62a80c852fc38a1ca1
 *       rpcd   d99f703e4035d03fbcfbada3cb697db346c2b984
 */

#include <ctype.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CT_PREFIX "application/x-www-form-urlencoded"
#define CT_PREFIX_LEN 33
#define REQ_SCOPE "cgi-io"
#define REQ_OBJECT "exec"
#define REQ_FUNCTION "read"
#define FILE_SCOPE "file"
#define FILE_FUNCTION "exec"
#define CGI_IO_SHA "31cb3c89f02d918d7f17bf62a80c852fc38a1ca1"

static const char *HELPERS[] = {
	"/usr/libexec/syslog-wrapper",
	"/usr/libexec/luci-peeraddr",
	"/usr/libexec/package-manager-call",
	NULL
};

static const char *arg_or_null(const char *s)
{
	if (s == NULL || strcmp(s, "-") == 0)
		return NULL;
	return s;
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

static int scope_match(const char *pat_scope, const char *scope)
{
	return strcmp(pat_scope, scope) == 0;
}

static int content_type_ok(const char *ct)
{
	return ct != NULL && strncmp(ct, CT_PREFIX, CT_PREFIX_LEN) == 0;
}

static int helper_found(const char *canon)
{
	int i;

	if (canon == NULL)
		return 0;
	for (i = 0; HELPERS[i]; i++) {
		if (strcmp(canon, HELPERS[i]) == 0)
			return 1;
	}
	return 0;
}

static char *datadup(const void *in, size_t len)
{
	char *out = malloc(len + 1);

	if (out == NULL)
		return NULL;
	memcpy(out, in, len);
	out[len] = 0;
	return out;
}

/* cgi-io util.c canonicalize_path @ 31cb3c89 */
static char *canonicalize_path(const char *path, size_t len)
{
	char *canonpath, *cp;
	const char *p, *e;

	if (path == NULL || *path == '\0')
		return NULL;

	canonpath = datadup(path, len);
	if (canonpath == NULL)
		return NULL;

	for (cp = canonpath, p = path, e = path + len; p < e; ) {
		if (*p != '/')
			goto next;

		if ((p + 1 < e) && (p[1] == '/')) {
			p++;
			continue;
		}

		if ((p + 1 < e) && (p[1] == '.')) {
			if ((p + 2 >= e) || (p[2] == '/')) {
				p += 2;
				continue;
			}

			if ((p + 2 < e) && (p[2] == '.') &&
			    ((p + 3 >= e) || (p[3] == '/'))) {
				while ((cp > canonpath) && (*--cp != '/'))
					;
				p += 3;
				continue;
			}
		}

next:
		*cp++ = *p++;
	}

	if ((cp > canonpath + 1) && (cp[-1] == '/'))
		cp--;
	else if (cp == canonpath)
		*cp++ = '/';

	*cp = '\0';
	return canonpath;
}

/* cgi-io util.c parse_command @ 31cb3c89 */
static char **parse_command(const char *cmdline)
{
	const char *p = cmdline, *s;
	char **argv = NULL, *out;
	size_t arglen = 0;
	int argnum = 0;
	int esc;

	while (isspace((unsigned char)*cmdline))
		cmdline++;

	for (p = cmdline, s = p, esc = 0; p; p++) {
		if (esc) {
			esc = 0;
		} else if (*p == '\\' && p[1] != 0) {
			esc = 1;
		} else if (isspace((unsigned char)*p) || *p == 0) {
			if (p > s) {
				argnum += 1;
				arglen += sizeof(char *) + (size_t)(p - s) + 1;
			}
			s = p + 1;
		}
		if (*p == 0)
			break;
	}

	if (arglen == 0)
		return NULL;

	argv = calloc(1, arglen + sizeof(char *));
	if (!argv)
		return NULL;

	out = (char *)argv + sizeof(char *) * (size_t)(argnum + 1);
	argv[0] = out;

	for (p = cmdline, s = p, esc = 0, argnum = 0; p; p++) {
		if (esc) {
			esc = 0;
			*out++ = *p;
		} else if (*p == '\\' && p[1] != 0) {
			esc = 1;
		} else if (isspace((unsigned char)*p) || *p == 0) {
			if (p > s) {
				*out++ = ' ';
				argv[++argnum] = out;
			}
			s = p + 1;
		} else {
			*out++ = *p;
		}
		if (*p == 0)
			break;
	}

	argv[argnum] = NULL;
	out[-1] = 0;
	return argv;
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

static int cmd_canon(int argc, char **argv)
{
	char *canon;

	if (argc != 1) {
		fprintf(stderr, "canon: expected 1 arg\n");
		return 2;
	}
	canon = canonicalize_path(argv[0], strlen(argv[0]));
	if (canon == NULL) {
		puts("NULL");
		return 1;
	}
	puts(canon);
	free(canon);
	return 0;
}

static int cmd_parse_command(int argc, char **argv)
{
	char **args;
	int i;

	if (argc != 1) {
		fprintf(stderr, "parse_command: expected 1 arg\n");
		return 2;
	}
	args = parse_command(argv[0]);
	if (!args) {
		puts("NULL");
		return 1;
	}
	for (i = 1; args[i]; i++)
		args[i][-1] = 0;
	for (i = 0; args[i]; i++)
		printf("%s\n", args[i]);
	free(args);
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
	const char *content_type, *sid, *command;
	const char *cgi_scope, *cgi_obj, *cgi_fun;
	const char *file_cmd_pat, *file_cmd_fun;
	const char *file_exe_pat, *file_exe_fun;
	char **args, *canon, *cmdline;
	size_t exelen;

	if (argc != 10) {
		fprintf(stderr, "decide: expected 10 args\n");
		return 2;
	}

	content_type = arg_or_null(argv[0]);
	sid = arg_or_null(argv[1]);
	command = arg_or_null(argv[2]);
	cgi_scope = argv[3];
	cgi_obj = argv[4];
	cgi_fun = argv[5];
	file_cmd_pat = arg_or_null(argv[6]);
	file_cmd_fun = arg_or_null(argv[7]);
	file_exe_pat = arg_or_null(argv[8]);
	file_exe_fun = arg_or_null(argv[9]);

	if (gate_parse(content_type, sid) != 0)
		return 1;

	if (!(scope_match(cgi_scope, REQ_SCOPE) &&
	      acl_match(cgi_obj, cgi_fun, REQ_OBJECT, REQ_FUNCTION))) {
		puts("HTTP_403");
		return 1;
	}

	args = parse_command(command);
	if (!args) {
		puts("HTTP_400");
		return 1;
	}

	exelen = args[1] ? (size_t)(args[1] - args[0] - 1) : strlen(args[0]);
	canon = canonicalize_path(args[0], exelen);
	if (!canon) {
		free(args);
		puts("HTTP_400");
		return 1;
	}

	cmdline = malloc(strlen(canon) + strlen(args[0] + exelen) + 1);
	if (!cmdline) {
		free(canon);
		free(args);
		puts("HTTP_500");
		return 1;
	}
	strcpy(cmdline, canon);
	strcat(cmdline, args[0] + exelen);

	if (!helper_found(canon)) {
		free(cmdline);
		free(canon);
		free(args);
		puts("HTTP_404");
		return 1;
	}

	if (file_cmd_pat && file_cmd_fun &&
	    acl_match(file_cmd_pat, file_cmd_fun, cmdline, FILE_FUNCTION)) {
		puts("ALLOW");
		free(cmdline);
		free(canon);
		free(args);
		return 0;
	}
	if (file_exe_pat && file_exe_fun &&
	    acl_match(file_exe_pat, file_exe_fun, canon, FILE_FUNCTION)) {
		puts("ALLOW");
		free(cmdline);
		free(canon);
		free(args);
		return 0;
	}

	puts("HTTP_403");
	free(cmdline);
	free(canon);
	free(args);
	return 1;
}

static int cmd_flags(void)
{
	printf("CGI_IO_SHA=%s\n", CGI_IO_SHA);
	printf("CT_PREFIX=%s\n", CT_PREFIX);
	printf("REQ_SCOPE=%s\n", REQ_SCOPE);
	printf("REQ_OBJECT=%s\n", REQ_OBJECT);
	printf("REQ_FUNCTION=%s\n", REQ_FUNCTION);
	printf("FILE_SCOPE=%s\n", FILE_SCOPE);
	printf("FILE_FUNCTION=%s\n", FILE_FUNCTION);
	printf("FNM_NOESCAPE=%d\n", FNM_NOESCAPE);
	return 0;
}

static void usage(FILE *fp)
{
	fprintf(fp,
		"usage: cgi_exec_file parse <content_type|-> <sessionid|->\n"
		"       cgi_exec_file canon <path>\n"
		"       cgi_exec_file parse_command <command>\n"
		"       cgi_exec_file match <scope_pat> <obj_pat> <fun_pat> <scope> <object> <function>\n"
		"       cgi_exec_file decide <ct|-> <sid|-> <command|-> <cgi_scope> <cgi_obj> <cgi_fun> <file_cmd_pat|-> <file_cmd_fun|-> <file_exe_pat|-> <file_exe_fun|->\n"
		"       cgi_exec_file flags\n");
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
	if (strcmp(cmd, "canon") == 0)
		return cmd_canon(argc - 2, argv + 2);
	if (strcmp(cmd, "parse_command") == 0)
		return cmd_parse_command(argc - 2, argv + 2);
	if (strcmp(cmd, "match") == 0)
		return cmd_match(argc - 2, argv + 2);
	if (strcmp(cmd, "decide") == 0)
		return cmd_decide(argc - 2, argv + 2);
	if (strcmp(cmd, "flags") == 0)
		return cmd_flags();

	usage(stderr);
	return 2;
}
