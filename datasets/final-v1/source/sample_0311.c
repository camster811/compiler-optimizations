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
        int * alias = data;
        int * data = alias;
        {
            int source[10] = {0};
            size_t i;
            for (i = 0; i < 10; i++)
            {
                data[i] = source[i];
            }
            printf("%d\n", data[0]);
            free(data);
        }
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
