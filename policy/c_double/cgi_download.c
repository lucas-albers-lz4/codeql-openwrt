/*
 * Isolated double of cgi-io main_download @ 31cb3c89f02d918d7f17bf62a80c852fc38a1ca1:
 *   Inputs are already-decoded form fields. Successful CONTENT_LENGTH/body
 *   framing and URL decoding are preconditions; those postdecode failures
 *   are not modeled by this authorization double.
 *   postdecode sessionid + path (application/x-www-form-urlencoded)
 *   session_access(sid, "cgi-io", "download", "read")
 *   canonicalize_path(path)
 *   session_access(sid, "file", canon, "read")
 *
 * Does not open, stat, or sendfile the target. No live ubus/cgi-io.
 * Does not model cgi-upload, cgi-exec, or cgi-backup.
 *
 * Build (record these flags in cgi_download_decisions.json harness):
 *   gcc -std=c11 -Wall -Wextra -Werror -O0 -o cgi_download cgi_download.c
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
#define REQ_OBJECT "download"
#define REQ_FUNCTION "read"
#define FILE_SCOPE "file"
#define FILE_FUNCTION "read"
#define CGI_IO_SHA "31cb3c89f02d918d7f17bf62a80c852fc38a1ca1"

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
	const char *content_type, *sid, *raw_path;
	const char *cgi_scope, *cgi_obj, *cgi_fun;
	const char *file_pat, *file_fun;
	char *canon;

	if (argc != 8) {
		fprintf(stderr, "decide: expected 8 args\n");
		return 2;
	}

	content_type = arg_or_null(argv[0]);
	sid = arg_or_null(argv[1]);
	raw_path = arg_or_null(argv[2]);
	cgi_scope = argv[3];
	cgi_obj = argv[4];
	cgi_fun = argv[5];
	file_pat = argv[6];
	file_fun = argv[7];

	if (gate_parse(content_type, sid) != 0)
		return 1;

	if (!(scope_match(cgi_scope, REQ_SCOPE) &&
	      acl_match(cgi_obj, cgi_fun, REQ_OBJECT, REQ_FUNCTION))) {
		puts("HTTP_403");
		return 1;
	}

	canon = raw_path ? canonicalize_path(raw_path, strlen(raw_path)) : NULL;
	if (canon == NULL) {
		puts("HTTP_403");
		return 1;
	}

	if (!(scope_match(FILE_SCOPE, FILE_SCOPE) &&
	      acl_match(file_pat, file_fun, canon, FILE_FUNCTION))) {
		free(canon);
		puts("HTTP_403");
		return 1;
	}

	puts("ALLOW");
	free(canon);
	return 0;
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
		"usage: cgi_download parse <content_type|-> <sessionid|->\n"
		"       cgi_download canon <path>\n"
		"       cgi_download match <scope_pat> <obj_pat> <fun_pat> <scope> <object> <function>\n"
		"       cgi_download decide <content_type|-> <sessionid|-> <path|-> "
		"<cgi_scope_pat> <cgi_obj_pat> <cgi_fun_pat> <file_pat> <file_fun>\n"
		"       cgi_download flags\n");
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
