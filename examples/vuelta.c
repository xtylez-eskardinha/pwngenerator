#include <stdio.h>
#include <string.h>

#define MAX_STRING_LENGTH 1000

int main() {
    char str[MAX_STRING_LENGTH];
    int length, i;

    // Solicitar la frase del usuario
    printf("Introduce una frase: ");
    fgets(str, MAX_STRING_LENGTH, stdin);

    // Eliminar el salto de línea que fgets agrega al final de la cadena
    str[strcspn(str, "\n")] = '\0';

    // Calcular la longitud de la cadena
    length = strlen(str);

    // Invertir la cadena
    printf("Frase invertida: ");
    for (i = length - 1; i >= 0; i--) {
        printf("%c", str[i]);
    }
    printf("\n");

    return 0;
}
