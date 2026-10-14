#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

void copy_payload(void)
{
    char * data;
    char * region_a = (char *)__builtin_alloca(50*sizeof(char));
    char * region_b = (char *)__builtin_alloca(100*sizeof(char));
    data = region_a;
    data[0] = '\0';
    {
        char source[100];
        memset(source, 'C', 100-1);
        source[100-1] = '\0';
        strncat(data, source, 100);
        puts(data);
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
