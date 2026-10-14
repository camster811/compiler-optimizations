#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

void copy_payload(void)
{
    int * data;
    data = NULL;
    data = (int *)__builtin_alloca(10*sizeof(int));
    {
        int source[10] = {0};
        memmove(data, source, 10*sizeof(int));
        printf("%d\n", data[0]);
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
