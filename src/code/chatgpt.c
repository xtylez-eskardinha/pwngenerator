#include <stdio.h>

int main() {
    char birthday[11]; // Array to hold the date in format "MM/DD/YYYY"

    // Prompt the user for their birthday
    printf("Please enter your birthday (MM/DD/YYYY): ");
    
    // Read the input from the user
    fgets(birthday, sizeof(birthday), stdin);
    
    // Remove newline character if present
    for(int i = 0; birthday[i] != '\0'; i++) {
        if (birthday[i] == '\n') {
            birthday[i] = '\0';
            break;
        }
    }

    // Print the entered birthday
    printf("Your birthday is: %s\n", birthday);

    return 0;
}
