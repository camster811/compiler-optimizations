#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

void copy_payload(void)
{
    int64_t * data;
    data = NULL;
    data = (int64_t *)malloc(50*sizeof(int64_t));
    if (data == NULL) {exit(-1);}
    {
        int64_t source[100] = {0};
        memcpy(data, source, 100*sizeof(int64_t));
        printf("%lld\n", (long long)(data[0]));
        free(data);
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
