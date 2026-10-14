#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#define PAYLOAD "AAAAAAAAAA"

void copy_payload(void)
{
    char * data;
    char * region_a = (char *)__builtin_alloca((10)*sizeof(char));
    char * region_b = (char *)__builtin_alloca((10+1)*sizeof(char));
    data = region_a;
    data[0] = '\0';
    {
        char * alias = data;
        char * data = alias;
        {
            char source[10+1] = PAYLOAD;
            strcpy(data, source);
            puts(data);
        }
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
