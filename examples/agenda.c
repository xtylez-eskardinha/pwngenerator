#include <stdio.h>

#define MAX_STRING_LENGTH 100

int main() {
    char first_name[MAX_STRING_LENGTH];
    char last_name[MAX_STRING_LENGTH];

    // Solicitar el nombre del usuario
    printf("Introduce tu nombre: ");
    scanf("%s", first_name);

    // Solicitar el apellido del usuario
    printf("Introduce tu apellido: ");
    scanf("%s", last_name);

    // Imprimir el nombre completo
    printf("Nombre completo: %s %s\n", first_name, last_name);

    return 0;
}
