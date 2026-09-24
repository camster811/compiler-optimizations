#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSG_LEN 10

static const char src[MSG_LEN + 1] = "AAAAAAAAAA";

void copy_message(void)
{
    char *buf = (char *)malloc(11 * sizeof(char));
    strcpy(buf, src);
    puts(buf);
    free(buf);
}

int main(void)
{
    copy_message();
    return 0;
}
