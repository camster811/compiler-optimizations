#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

void copy_payload(void)
{
    int64_t * data;
    int64_t * region_a = (int64_t *)__builtin_alloca(50*sizeof(int64_t));
    int64_t * region_b = (int64_t *)__builtin_alloca(100*sizeof(int64_t));
    data = region_a;
    {
        int64_t source[100] = {0};
        memcpy(data, source, 100*sizeof(int64_t));
        printf("%lld\n", (long long)(data[0]));
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
