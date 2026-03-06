#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // VULNERABLE: strcpy does not check bounds before copying input into the 64-byte buffer.
    strcpy(buffer, input);
    printf("Input copied successfully: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
