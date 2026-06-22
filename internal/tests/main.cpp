#include <cstdio>
#include <cstring>

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    printf("  Running %s ... ", #name); \
    test_##name(); \
    printf("OK\n"); \
} while(0)

// Test declarations
extern void test_cpuid_spoofs();
extern void test_kuser_sync();
extern void test_syscall_dispatch();
extern void test_profile_load();

int main()
{
    printf("emu - Test Suite\n");
    printf("============================\n\n");

    RUN_TEST(cpuid_spoofs);
    RUN_TEST(kuser_sync);
    RUN_TEST(syscall_dispatch);
    RUN_TEST(profile_load);

    printf("\nAll tests passed!\n");
    return 0;
}
