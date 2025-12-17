#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

double getrandom(){
    char chunk_array[8];
    double randomer;
    int flagA;
    srand((time(NULL)/20)); // 20
    randomer = (double)rand() / RAND_MAX;
    unsigned char byte_array[8];

    // Step 1: Convert double to byte array
    memcpy(byte_array, &randomer, sizeof(double));
    // Step 2: Transform each byte
    for (int i = 0; i < 8; ++i) {
        byte_array[i] = byte_array[i] % 126; // Apply modulus 126
        if (byte_array[i] < 33) {
            byte_array[i] += 33; // If the byte is less than 33, add 33
        }
    }
    // Step 3: Convert modified byte array back to double
    memcpy(&randomer, byte_array, sizeof(double));
    //printf("Transformed double: %f\n", transformed_value);
    return randomer;
}

int main(int argc, char *argv) {
    double random_double = getrandom();
    unsigned char random_bytes[8];
    unsigned char user_input[72];
    char random_hex[17]; // 8 bytes = 16 hex chars + null terminator
    
    // Copy the random double to bytes
    memcpy(random_bytes, &random_double, sizeof(double));
    
    // Convert random bytes to hex string
    for (int i = 0; i < 8; i++) {
        sprintf(&random_hex[i * 2], "%02x", random_bytes[i]);
    }
    random_hex[16] = '\0';
    
    printf("Enter the number:\n");
    fgets(user_input, sizeof(user_input), stdin);
    user_input[strcspn(user_input, "\n")] = 0;
    
    if (strcmp(user_input, random_hex) == 0) {
        char flag[78];
        FILE *fin;
        fin = fopen("01_flag.txt", "r");
        if (fin == NULL){
            printf("\ncuhk25ctf2{FaKe_flag_in_Registrationnnn}.\n");
            exit(999);
        }
        fgets(flag, 78, fin);
        printf("%s\n", flag);
    } else {
        printf("\nNo idea why you still cannot solve it...\n");
    }
    return 0;

}