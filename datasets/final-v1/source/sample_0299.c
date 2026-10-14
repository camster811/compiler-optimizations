#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

void copy_payload(void)
{
    wchar_t * data;
    wchar_t * region_a = (wchar_t *)__builtin_alloca(50*sizeof(wchar_t));
    wchar_t * region_b = (wchar_t *)__builtin_alloca(100*sizeof(wchar_t));
    data = region_a;
    data[0] = L'\0';
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1);
        source[100-1] = L'\0';
        wcsncat(data, source, 100);
        wprintf(L"%ls\n", data);
    }
}

int main(void)
{
    copy_payload();
    return 0;
}
