/* Independent direct libc verification of the pinned witness. */
#include <fnmatch.h>
#include <locale.h>
#include <stdio.h>
int main(void) {
    const char *a = "/proc/sys/net/ipv6/conf/*/mtu";
    const char *b = "/proc/sys/net/ipv[46]/conf/*";
    const char *v = "/proc/sys/net/ipv6/conf/eth0/mtu";
    if (!setlocale(LC_ALL, "C")) return 2;
    if (fnmatch(a, v, FNM_NOESCAPE) || fnmatch(b, v, FNM_NOESCAPE) ||
        fnmatch(b, v, FNM_NOESCAPE | FNM_PATHNAME) != FNM_NOMATCH ||
        fnmatch(b, "/proc/sys/net/ipv5/conf/eth0/mtu", FNM_NOESCAPE) != FNM_NOMATCH)
        return 1;
    puts(v);
    return 0;
}
