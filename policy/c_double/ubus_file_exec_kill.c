/*
 * Isolated double of HTTP /ubus file.exec @ rpcd d99f703:
 *   uhttpd parse_call_params + uh_ubus_allowed (session.access
 *   scope=ubus object=file function=exec; uhttpd omits scope)
 *   rpcd-mod-file rpc_file_exec_run:
 *     rpc_file_exec_lookup (inventoried absolute paths only)
 *     rpc_canonicalize_path
 *     rpc_file_access(sid, executable, exec) then, on miss,
 *     rpc_file_access(sid, cmdline, exec)
 *
 * Bounded to luci-mod-status-processes write /bin/kill
 * reached via fs.exec at luci b2e0be4b. lookup is not a live
 * PATH/stat search. Does not fork execv. No live ubus/rpcd.
 *
 * Build:
 *   gcc -std=c11 -Wall -Wextra -Werror -O0 -o ubus_file_exec_kill ubus_file_exec_kill.c
 *
 * Pins: uhttpd 93b05e0b65d91c23c5aa8fdde378df1f174ec71d
 *       rpcd   d99f703e4035d03fbcfbada3cb697db346c2b984
 */

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UBUS_OBJECT "file"
#define UBUS_METHOD "exec"
#define FILE_SCOPE "file"
#define FILE_FUNCTION "exec"
#define RPCD_SHA "d99f703e4035d03fbcfbada3cb697db346c2b984"
#define RPC_CMDLINE_MAX_SIZE 1024

static const char *HELPERS[] = {
	"/bin/kill",
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

static int helper_found(const char *cmd)
{
	int i;

	if (cmd == NULL)
		return 0;
	for (i = 0; HELPERS[i]; i++) {
		if (strcmp(cmd, HELPERS[i]) == 0)
			return 1;
	}
	return 0;
}

static char *datadup(const char *in)
{
	size_t len = strlen(in);
	char *out = malloc(len + 1);

	if (out == NULL)
		return NULL;
	memcpy(out, in, len + 1);
	return out;
}

/* rpcd file.c rpc_canonicalize_path @ d99f703 */
static char *canonicalize_path(const char *path)
{
	char *canonpath, *cp;
	const char *p;

	if (path == NULL || *path == '\0')
		return NULL;

	canonpath = datadup(path);
	if (canonpath == NULL)
		return NULL;

	for (cp = canonpath, p = path; *p != '\0'; ) {
		if (*p != '/')
			goto next;

		if (p[1] == '/') {
			p++;
			continue;
		}

		if (p[1] == '.') {
			if ((p[2] == '\0') || (p[2] == '/')) {
				p += 2;
				continue;
			}

			if ((p[2] == '.') && ((p[3] == '\0') || (p[3] == '/'))) {
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
	if (sid == NULL || object == NULL || function == NULL || data == NULL) {
		puts("ERROR_PARSE");
		return 1;
	}
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
	canon = canonicalize_path(argv[0]);
	if (canon == NULL) {
		puts("NULL");
		return 1;
	}
	puts(canon);
	free(canon);
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
	const char *sid, *command, *params;
	const char *ubus_obj_pat, *ubus_fun_pat;
	const char *file_exe_pat, *file_exe_fun;
	const char *file_cmd_pat, *file_cmd_fun;
	char *canon, cmdstr[RPC_CMDLINE_MAX_SIZE];

	if (argc != 9 && argc != 10) {
		fprintf(stderr, "decide: expected 9 or 10 args\n");
		return 2;
	}

	sid = arg_or_null(argv[0]);
	command = arg_or_null(argv[1]);
	params = arg_or_null(argv[2]);
	ubus_obj_pat = arg_or_null(argv[3]);
	ubus_fun_pat = arg_or_null(argv[4]);
	file_exe_pat = arg_or_null(argv[5]);
	file_exe_fun = arg_or_null(argv[6]);
	file_cmd_pat = arg_or_null(argv[7]);
	file_cmd_fun = arg_or_null(argv[8]);

	if (sid == NULL) {
		puts("ERROR_PARSE");
		return 1;
	}

	if (!(ubus_obj_pat && ubus_fun_pat &&
	      acl_match(ubus_obj_pat, ubus_fun_pat, UBUS_OBJECT, UBUS_METHOD))) {
		puts("ERROR_ACCESS");
		return 1;
	}

	if (command == NULL) {
		puts("UBUS_INVALID_ARGUMENT");
		return 1;
	}

	/* A present env TABLE is rejected with a present SID, even if empty. */
	if (sid && argc == 10 && atoi(argv[9])) {
		puts("UBUS_PERMISSION_DENIED");
		return 1;
	}

	if (!helper_found(command)) {
		puts("UBUS_NOT_FOUND");
		return 1;
	}

	canon = canonicalize_path(command);
	if (canon == NULL) {
		puts("UBUS_NOT_FOUND");
		return 1;
	}

	if (file_exe_pat && file_exe_fun &&
	    acl_match(file_exe_pat, file_exe_fun, canon, FILE_FUNCTION)) {
		puts("ALLOW");
		free(canon);
		return 0;
	}

	if (params == NULL) {
		puts("UBUS_PERMISSION_DENIED");
		free(canon);
		return 1;
	}

	if (strlen(canon) + 1 + strlen(params) >= sizeof(cmdstr)) {
		puts("UBUS_PERMISSION_DENIED");
		free(canon);
		return 1;
	}
	snprintf(cmdstr, sizeof(cmdstr), "%s %s", canon, params);

	if (file_cmd_pat && file_cmd_fun &&
	    acl_match(file_cmd_pat, file_cmd_fun, cmdstr, FILE_FUNCTION)) {
		puts("ALLOW");
		free(canon);
		return 0;
	}

	puts("UBUS_PERMISSION_DENIED");
	free(canon);
	return 1;
}

static int cmd_flags(void)
{
	printf("RPCD_SHA=%s\n", RPCD_SHA);
	printf("UBUS_OBJECT=%s\n", UBUS_OBJECT);
	printf("UBUS_METHOD=%s\n", UBUS_METHOD);
	printf("FILE_SCOPE=%s\n", FILE_SCOPE);
	printf("FILE_FUNCTION=%s\n", FILE_FUNCTION);
	printf("FNM_NOESCAPE=%d\n", FNM_NOESCAPE);
	return 0;
}

static void usage(FILE *fp)
{
	fprintf(fp,
		"usage: ubus_file_exec_kill parse <sid|-> <object|-> <function|-> <data|->\n"
		"       ubus_file_exec_kill canon <path>\n"
		"       ubus_file_exec_kill match <obj_pat> <fun_pat> <object> <function>\n"
		"       ubus_file_exec_kill decide <sid|-> <command|-> <params|-> <ubus_obj_pat|-> <ubus_fun_pat|-> <file_exe_pat|-> <file_exe_fun|-> <file_cmd_pat|-> <file_cmd_fun|-> [env_present:0|1]\n"
		"       ubus_file_exec_kill flags\n");
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
	if (strcmp(cmd, "match") == 0)
		return cmd_match(argc - 2, argv + 2);
	if (strcmp(cmd, "decide") == 0)
		return cmd_decide(argc - 2, argv + 2);
	if (strcmp(cmd, "flags") == 0)
		return cmd_flags();

	usage(stderr);
	return 2;
}
