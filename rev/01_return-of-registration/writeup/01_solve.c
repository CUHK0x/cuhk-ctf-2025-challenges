#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

double getrandom(){
    double randomer;
    srand((time(NULL)/20));
    randomer = (double)rand() / RAND_MAX;
    unsigned char byte_array[8];

    memcpy(byte_array, &randomer, sizeof(double));
    for (int i = 0; i < 8; ++i) {
        byte_array[i] = byte_array[i] % 126;
        if (byte_array[i] < 33) {
            byte_array[i] += 33;
        }
    }
    memcpy(&randomer, byte_array, sizeof(double));
    return randomer;
}

int main() {
    double random_double = getrandom();
    unsigned char random_bytes[8];
    char hex_value[17] = {0};
    
    memcpy(random_bytes, &random_double, sizeof(double));
    
    for (int i = 0; i < 8; i++) {
        sprintf(&hex_value[i * 2], "%02x", random_bytes[i]);
    }
    
    printf("The hex value you need to enter is: %s\n", hex_value);
    printf("Run the challenge program and input this value.\n");
    
    return 0;
}
