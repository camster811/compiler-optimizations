#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

void copy_payload(void)
{
    wchar_t * data;
    data = NULL;
    data = (wchar_t *)malloc(50*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1);
        source[100-1] = L'\0';
        wcsncat(data, source, 100);
        wprintf(L"%ls\n", data);
        free(data);
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
