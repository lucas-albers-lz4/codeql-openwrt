#include <fnmatch.h>
#include <locale.h>
int main(int argc, char **argv) {
    int a, b;
    if (argc != 4 || !setlocale(LC_ALL, "C")) return 2;
    a = fnmatch(argv[1], argv[3], FNM_NOESCAPE);
    b = fnmatch(argv[2], argv[3], FNM_NOESCAPE);
    if ((a != 0 && a != FNM_NOMATCH) || (b != 0 && b != FNM_NOMATCH)) return 2;
    return a == 0 && b == 0 ? 0 : 1;
}
