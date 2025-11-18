#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>

typedef unsigned long (*getauxval_fn)(unsigned long);

static getauxval_fn resolve_real(void) {
    static getauxval_fn real = NULL;
    if (real != NULL) {
        return real;
    }
    void *symbol = dlsym(RTLD_NEXT, "getauxval");
    if (symbol != NULL) {
        real = (getauxval_fn)symbol;
    }
    return real;
}

unsigned long getauxval(unsigned long type) {
    if (type == AT_SYSINFO_EHDR) {
        return 0;
    }
    getauxval_fn real = resolve_real();
    if (real == NULL) {
        return 0;
    }
    return real(type);
}
