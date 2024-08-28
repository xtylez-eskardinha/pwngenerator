#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void ret2win(){
    system("/bin/sh");
}

void input_gets_bof(char *buf) {
    char filler[64];
    char buffer[64];
    gets(buffer);
    strncpy(buf, buffer, sizeof(buffer));
}

void input_fgets_bof(char *buf){
    char filler[64];
    char buffer[64];
    fgets(buffer, sizeof(filler) + sizeof(buffer)*2, stdin);
    strncpy(buf, buffer, sizeof(buffer));
}

void input_fgets_bof_canary(char *buf){
    int canary = 0x42;
    char filler[64];
    char buffer[64];
    fgets(buffer, sizeof(buffer) + sizeof(filler)*2, stdin);
    if (canary != 0x42)
        exit(139);
    strncpy(buf, buffer, sizeof(buffer));
}

void input_gets_bof_canary(char *buf) {
    int canary = 0x42;
    char filler[64];
    char buffer[64];
    gets(buffer);
    if (canary != 0x42)
        exit(139);
    strncpy(buf, buffer, sizeof(buffer));
}

void input_scanf_bof(char *buf) {
    char filler[64];
    char buffer[64];
    scanf("%s", buffer);
    strncpy(buf, buffer, sizeof(buffer));
}

void input_scanf_bof_canary(char *buf) {
    int canary = 0x42;
    char filler[64];
    char buffer[64];
    scanf("%s", buffer);
    if (canary != 0x42)
        exit(139);
    strncpy(buf, buffer, sizeof(buffer));
}


void input_strcpy_bof(char *buf) {
    char filler[64];
    char buffer2[64];
    fgets(buffer2, sizeof(filler)*2 + sizeof(buffer2), stdin);
    strncpy(buf, buffer2, sizeof(buffer2));
}

void input_strcpy_bof_canary(char *buf) {
    int canary = 0x42;
    char filler[64];
    char buffer2[64];
    fgets(buffer2, sizeof(filler)*2 + sizeof(buffer2), stdin);
    if (canary != 0x42)
        exit(139);
    strncpy(buf, buffer2, sizeof(buffer2));
}

void append_input_bof(char *buf) {
    char filler[64];
    char buffer[64];
    scanf("%s", buffer);
    strcat(buf, buffer);
}

void easy_leak() {
    do
    {
        char init[16];
        printf("\nBut first, I'll print what you type, max 16 bytes, take it as a gift: ");
        fgets(init, sizeof(init), stdin);
        printf(init);
        printf("\n");
        printf("Now you can continue with what I asked you before :) \n");
        /* code */
    } while (0);
}

void leak_stack_printf(char *buf) {
    printf(buf);
}

void leak_stack_printf_custom(char *buf, int *a) {
    printf("Prev");
    printf("FMT", buf);
    printf("POST");
}

void leak_stack_sprintf(char *buf, char *dest) {
    sprintf(dest, buf);
}
