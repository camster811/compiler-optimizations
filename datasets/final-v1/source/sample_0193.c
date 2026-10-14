#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

void copy_payload(void)
{
    int * data;
    data = NULL;
    data = (int *)malloc(10*sizeof(int));
    if (data == NULL) {exit(-1);}
    {
        int source[10] = {0};
        memcpy(data, source, 10*sizeof(int));
        printf("%d\n", data[0]);
        free(data);
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
