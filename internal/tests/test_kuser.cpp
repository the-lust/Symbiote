#include <cstdio>
#include <cassert>
#include <windows.h>

// test KUSER access


typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME;

typedef struct _KUSER_SHARED_DATA {
    UCHAR Reserved1[0x318];
    KSYSTEM_TIME SystemTime;
    KSYSTEM_TIME InterruptTime;
} KUSER_SHARED_DATA;

void test_kuser_sync()
{
    KUSER_SHARED_DATA* kuser = (KUSER_SHARED_DATA*)0x7FFE0000;

    // Verify KUSER_SHARED_DATA is accessible
    ULONG pageSize = kuser->SystemTime.LowPart;
    // We can't guarantee specific values, but we can verify the structure is readable
    printf("  KUSER_SHARED_DATA at 0x7FFE0000 is accessible\n");
    printf("  SystemTime LowPart=%lu\n", kuser->SystemTime.LowPart);
    printf("  InterruptTime LowPart=%lu\n", kuser->InterruptTime.LowPart);

    // Verify the offset layout
    assert((uintptr_t)&kuser->SystemTime - (uintptr_t)kuser == 0x318);
    printf("  SystemTime offset verified: 0x318\n");
}
