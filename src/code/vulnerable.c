#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void input_gets_bof() {
    char buffer[64];
    gets(buffer);
    return buffer;
}

void input_gets_bof_canary() {
    int canary = 0x20;
    char buffer[64];
    gets(buffer);
    if (canary != 0x20)
        exit(127);
    return buffer;
}

void input_strcpy_bof() {
    char buffer[24];
    char buffer2[64];
    fgets(buffer2, sizeof(buffer2), stdin);
    strcpy(buffer, buffer2);
    return buffer;
}

void input_strcpy_bof_canary() {
    int canary = 42;
    char buffer[32];
    char buffer3[64];
    fgets(buffer3, sizeof(buffer3), stdin);
    strcpy(buffer, buffer3);
    if (canary != 42)
        exit(127);
    return buffer;
}
