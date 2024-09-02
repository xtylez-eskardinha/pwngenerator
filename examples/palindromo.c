#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_STRING_LENGTH 1000

int isPalindrome(char str[]) {
    int start = 0;
    int end = strlen(str) - 1;

    while (start < end) {
        // Ignorar caracteres no alfanuméricos
        while (start < end && !isalnum(str[start])) {
            start++;
        }
        while (start < end && !isalnum(str[end])) {
            end--;
        }

        // Comparar caracteres
        if (tolower(str[start]) != tolower(str[end])) {
            return 0;  // No es palíndromo
        }
        start++;
        end--;
    }

    return 1;  // Es palíndromo
}

int main() {
    char str[MAX_STRING_LENGTH];

    // Solicitar la frase del usuario
    printf("Introduce una palabra o frase: ");
    fgets(str, MAX_STRING_LENGTH, stdin);

    // Eliminar el salto de línea que fgets agrega al final de la cadena
    str[strcspn(str, "\n")] = '\0';

    // Verificar si la cadena es palíndroma
    if (isPalindrome(str)) {
        printf("La palabra o frase es palíndroma.\n");
    } else {
        printf("La palabra o frase no es palíndroma.\n");
    }

    return 0;
}
