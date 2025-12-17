#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>

#define HASH_LENGTH EVP_MAX_MD_SIZE

int compute_sha256(const unsigned char* data, size_t length, unsigned char* hash, unsigned int* hash_length) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Failed to initialize SHA256\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (EVP_DigestUpdate(ctx, data, length) != 1) {
        fprintf(stderr, "Failed to update SHA256\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (EVP_DigestFinal_ex(ctx, hash, hash_length) != 1) {
        fprintf(stderr, "Failed to finalize SHA256\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

double getrandom(){
    char chunk_array[8];
    double randomer;
    int flagA;
    srand((time(NULL)/3600)); // 20
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

void xor_strings(const char* input, const char* key, unsigned char* output) {
    for (size_t i = 0; i < strlen(input); ++i) {
        output[i] = input[i] ^ key[i % strlen(key)];
    }
}

int main(int argc, char *argv) {
    double random_double = getrandom();
    unsigned char random_char[8];
    unsigned char user_input_array[72];
    unsigned char hash[HASH_LENGTH];
    unsigned char target_hash[HASH_LENGTH];
    unsigned char result_array[8];
    unsigned char xor_output[8];
    char maze[460] = "############################                         ## # ######### ########### ## #    ###### #   #   #   ## # ######### # # # # ###### # ####      # # # #     ## # #### ###### # # ##### ## # ####        # # #  ## ## # ######### ### # # ### ## #         # ### # #   # ## ########### ###   ### # ## #           ########  # ## # ###############    ## ## # #               ##### ## ####################  # ##                      ## ########################## #";
    int hash_length;
    //random_double = getrandom();
    memcpy(random_char, &random_double, sizeof(double));
    
    printf("Enter path: ");
    fgets(user_input_array, sizeof(user_input_array), stdin);
    //char hash_hex[HASH_LENGTH * 2 + 1];
    //fgets(hash_hex, sizeof(hash_hex), stdin);
    //hash_hex[strcspn(hash_hex, "\n")] = 0;
    user_input_array[strcspn(user_input_array, "\n")] = 0;
    uint64_t input_bits = *((uint64_t*)&random_char);
    printf("a!");
    
    xor_strings(user_input_array, random_char, xor_output);
    if (!compute_sha256(xor_output, 71, hash, &hash_length)) {
        return 1; // Error handling
    }
    printf("b!");
    
    char hash_hex[HASH_LENGTH * 2 + 1];
    for (unsigned int i = 0; i < hash_length; i++) {
        sprintf(&hash_hex[i * 2], "%02x", hash[i]);
    }
    hash_hex[hash_length * 2] = '\0';  // Null-terminate the hex string
    hash_hex[strcspn(hash_hex, "\n")] = 0;
    
    printf("C!");
    FILE *fhash;
    fhash = fopen("01_SHA256.txt", "r");
    if (fhash == NULL){
        printf("No SHA256 hash available.\n");
        exit(100);
    }
    printf("D!");
    char target_string[72];
    fgets(target_string, 72, fhash);
    printf("e!\n");
    printf("%s\n", target_string);
    printf("%s\n", hash_hex);
    // Check if the result matches the binary representation of the pre-determined string
    //const char* target_string = ;
    printf("%d\n", strcmp(hash_hex, target_string));
    if (strcmp(hash_hex, target_string) == 0) {
        char flag[50];
        FILE *fin;
        fin = fopen("01_flag.txt", "r");
        if (fin == NULL){
            printf("\ncuhk25ctf2{FaKe_flag_in_Registrationnnn}.\n");
            exit(999);
        }
        fgets(flag, 50, fin);
        printf("%s\n", flag);
    } else {
        printf("\nBoom!\n");
    }
    return 0;

}