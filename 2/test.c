#include <stdio.h>
#include <string.h>

char* sha256(char* ans) {
    for(int i=0; i<(int)strlen(ans); i++) {
        printf("%c ", ans[i]);
    }
    printf("\n%d \n", (int)strlen(ans));
    return ans;
}



int main() {
    char* ans;
    ans = "dsadsadsadsasaddas";
    sha256(ans);
    return 0;
}