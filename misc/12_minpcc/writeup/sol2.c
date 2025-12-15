#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Searches the memory in mem for at most count bytes to find a string matching target.
 */
const char *search(const char *mem, const char *tgt, size_t count) {
    const size_t tgt_len = strlen(tgt);
    size_t match_count = 0;
    for (int i = 0; i < count; i++) {
        if (mem[i] == tgt[match_count]) {
            match_count++;
            if (match_count == tgt_len) {
                return mem + i - (match_count - 1);
            }
        } else match_count = 0;
    }
    return NULL;
}

int main() {
    // Dig through the stack memory for the "FLAG" environment variable
    // Note that the stack grows upwards in x86_64, so it is correct that we search forward 
    char c;
    const char *var = search(&c, "FLAG", 8192);
    if (var == NULL) {
        puts("Not Found");
    } else puts(var);
    fflush(stdout);
    return 0;
}