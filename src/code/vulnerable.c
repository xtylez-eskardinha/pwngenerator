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
    strcpy(buf, buffer);
}

void input_fgets_bof(char *buf){
    char filler[64];
    char buffer[64];
    fgets(buffer, sizeof(filler) + sizeof(buffer)*2, stdin);
    strcpy(buf, buffer);
}

void input_fgets_bof_canary(char *buf){
    int canary = 0x20;
    char filler[64];
    char buffer[64];
    fgets(buffer, sizeof(filler) + sizeof(buffer)*2, stdin);
    if (canary != 0x20)
        exit(127);
    strcpy(buf, buffer);
}

void input_gets_bof_canary(char *buf) {
    int canary = 0x20;
    char filler[64];
    char buffer[64];
    gets(buffer);
    if (canary != 0x20)
        exit(127);
    strcpy(buf, buffer);
}

void input_scanf_bof(char *buf) {
    char filler[64];
    char buffer[64];
    scanf("%s", buffer);
    strcpy(buf, buffer);
}

void input_scanf_bof_canary(char *buf) {
    int canary = 0x20;
    char filler[64];
    char buffer[64];
    scanf("%s", buffer);
    if (canary != 0x20)
        exit(127);
    strcpy(buf, buffer);
}


void input_strcpy_bof(char *buf) {
    char filler[64];
    char buffer2[64];
    fgets(buffer2, sizeof(buffer2), stdin);
    strcpy(buf, buffer2);
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
        printf("\nBut first, I'll print what you type, take it as a gift: ");
        char* init[32];
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
