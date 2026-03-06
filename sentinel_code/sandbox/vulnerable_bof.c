#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // FIXED: strncpy ensures bounds checking before copying input into the 64-byte buffer, 
    //        and always null-terminates the buffer to prevent buffer overflows.
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null-termination
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