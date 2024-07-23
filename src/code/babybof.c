#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

int main(){
    printf("Tell me something and I'll answer you: ");
    char buffer[24];
    fgets(stdin, sizeof(buffer), buffer);
    puts(buffer);
    return 0;
}