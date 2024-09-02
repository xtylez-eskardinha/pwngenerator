#include <stdio.h>

void vulnerableFunction() {
    char buffer[10];  // Buffer de tamaño fijo

    printf("Introduce un texto: ");
    gets(buffer);  // Leer entrada del usuario sin límite de tamaño

    printf("Has introducido: %s\n", buffer);
}

int main() {
    vulnerableFunction();
    return 0;
}