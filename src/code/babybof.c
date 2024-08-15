#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

int main(){
    printf("Tell me something and I'll answer you: ");
    char buffer[24];
    char buffer2[24];
    char buffer3[24];
    scanf("%d %s %d", &buffer, &buffer2, &buffer3);
    puts(buffer2);
    return 0;
}
