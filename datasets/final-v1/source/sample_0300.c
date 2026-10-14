#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#define PAYLOAD "AAAAAAAAAA"

void copy_payload(void)
{
    char * data;
    data = NULL;
    data = (char *)malloc((10+1)*sizeof(char));
    if (data == NULL) {exit(-1);}
    {
        char source[10+1] = PAYLOAD;
        strncpy(data, source, strlen(source) + 1);
        puts(data);
        free(data);
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
