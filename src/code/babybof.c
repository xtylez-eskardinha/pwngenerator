#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void execme(){
	system("/bin/bash");
}

void get_input(char *buffer[]) {
    int canary = 42;
    char buffer3[64];
    char buffer2[24];
    scanf("%48s", buffer2); // Sustituir por get_input()
    printf("You've entered: %s\n", buffer2);
    strcpy(buffer2, buffer);
    if (canary != 42)
        exit(127);
}

void pwnable(){
   
}

int main(){
    printf("Tell me something and I'll answer you: ");
    char buffer[24];
    get_input(&buffer);
    return 0;
}