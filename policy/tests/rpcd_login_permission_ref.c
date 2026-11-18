/*
 * rpcd - UBUS RPC server
 *
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *   Copyright (C) 2013-2014 Jo-Philipp Wich <jow@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* rpc_login_test_permission copied verbatim from rpcd session.c at
 * d99f703e4035d03fbcfbada3cb697db346c2b984, lines 934-990.
 * Minimal UCI stand-ins and test wrapper are not native rpcd or libuci.
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <ctype.h>
#include <fnmatch.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

struct uci_element { const char *name; struct uci_element *next; };
struct uci_list { struct uci_element *head; };
struct uci_option {
    struct uci_element e;
    int type;
    union { struct uci_list list; } v;
};
struct uci_section { struct uci_list options; };
#define UCI_TYPE_LIST 1
#define uci_to_option(e) ((struct uci_option *)(e))
#define uci_foreach_element(list, e) for ((e) = (list)->head; (e); (e) = (e)->next)

static bool
rpc_login_test_permission(struct uci_section *s,
                          const char *perm, const char *group)
{
	const char *p;
	struct uci_option *o;
	struct uci_element *e, *l;

	/* If the login section is not provided, we're setting up acls for the
	 * default session, in this case uncondionally allow access to the
	 * "unauthenticated" access group */
	if (!s) {
		return !strcmp(group, "unauthenticated");
	}

	uci_foreach_element(&s->options, e)
	{
		o = uci_to_option(e);

		if (o->type != UCI_TYPE_LIST)
			continue;

		if (strcmp(o->e.name, perm))
			continue;

		/* Match negative expressions first. If a negative expression matches
		 * the current group name then deny access. */
		uci_foreach_element(&o->v.list, l) {
			p = l->name;

			if (!p || *p != '!')
				continue;

			while (isspace((unsigned char)*++p));

			if (!*p)
				continue;

			if (!fnmatch(p, group, 0))
				return false;
		}

		uci_foreach_element(&o->v.list, l) {
			if (!l->name || !*l->name || *l->name == '!')
				continue;

			if (!fnmatch(l->name, group, 0))
				return true;
		}
	}

	/* make sure that write permission implies read permission */
	if (!strcmp(perm, "read"))
		return rpc_login_test_permission(s, "write", group);

	return false;
}

/* Return -1 on setup failure, otherwise native permission as 0 or 1. */
int reference_permission(int default_session, const char *perm, const char *group,
                         const char **read, size_t nr, const char **write, size_t nw)
{
    locale_t c_locale = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    if (!c_locale) return -1;
    locale_t previous = uselocale(c_locale);
    if (!previous) { freelocale(c_locale); return -1; }
    struct uci_element *re = calloc(nr ? nr : 1, sizeof(*re));
    struct uci_element *we = calloc(nw ? nw : 1, sizeof(*we));
    if (!re || !we) {
        free(re); free(we); uselocale(previous); freelocale(c_locale);
        return -1;
    }
    for (size_t i = 0; i < nr; i++) {
        re[i].name = read[i];
        re[i].next = i + 1 < nr ? &re[i + 1] : NULL;
    }
    for (size_t i = 0; i < nw; i++) {
        we[i].name = write[i];
        we[i].next = i + 1 < nw ? &we[i + 1] : NULL;
    }
    struct uci_option options[2] = {
        { .e = { .name = "read", .next = &options[1].e },
          .type = UCI_TYPE_LIST, .v = { .list = { .head = nr ? re : NULL } } },
        { .e = { .name = "write", .next = NULL },
          .type = UCI_TYPE_LIST, .v = { .list = { .head = nw ? we : NULL } } },
    };
    struct uci_section section = { .options = { .head = &options[0].e } };
    bool result = rpc_login_test_permission(default_session ? NULL : &section, perm, group);
    free(re); free(we); uselocale(previous); freelocale(c_locale);
    return result;
}
