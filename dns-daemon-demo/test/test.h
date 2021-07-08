#include <assert.h>
#include <stdio.h>

#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            printf("%s:%d assertion fails: %s\n", __FILE__, __LINE__, #cond); \
            return false; \
        } \
    } while (0)

#define RUN_TEST(fn) \
    printf("%s ... %s\n", #fn, fn() ? "pass" : "fail")
