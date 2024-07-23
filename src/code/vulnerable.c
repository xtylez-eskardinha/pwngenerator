#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void ret2win(){
    system("/bin/sh");
}

void input_gets_bof(char *buf) {
    char buffer[64];
    gets(buffer);
    strcpy(buf, buffer);
}

void input_gets_bof_canary(char *buf) {
    int canary = 0x20;
    char buffer[64];
    gets(buffer);
    if (canary != 0x20)
        exit(127);
    strcpy(buf, buffer);
}

void input_scanf_bof(char *buf) {
    char buffer[64];
    scanf("%s", buffer);
    strcpy(buf, buffer);
}

void input_strcpy_bof(char *buf) {
    char buffer[24];
    char buffer2[64];
    fgets(buffer2, sizeof(buffer2), stdin);
    strcpy(buffer, buffer2);
}

void input_strcpy_bof_canary(char *buf) {
    int canary = 42;
    char buffer[32];
    char buffer3[64];
    fgets(buffer3, sizeof(buffer3), stdin);
    strcpy(buffer, buffer3);
    if (canary != 42)
        exit(127);
    return buffer;
}

void append_input_bof(char *buf) {
    char buffer[64];
    scanf("%s", buffer);
    strcat(buf, buffer);
}

void leak_stack_printf(char *buf) {
    printf(buf);
}

void leak_stack_sprintf(char *buf, char *dest) {
    sprintf(dest, buf);
}
