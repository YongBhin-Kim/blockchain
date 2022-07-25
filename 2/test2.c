#include <stdio.h>
#include <stdlib.h>
#include "aesLib.h"
#include <stdint.h>
#include <string.h>

void printState2(char* state, size_t size) {
    printf("\n[C] : 받은 s값 출력, char 자료형\n");
    for(int i=0; i<50; i++) {
        // if (i % 4 != 0) {
        printf("%02X ", state[i]);
        // }
    }
}
void printState3(uint8_t* state, size_t size) {
    printf("\n[C] : 받은 s값 출력, uint8_t 자료형\n");
    for(int i=0; i<50; i++) {
        // if (i % 4 != 0) {
        printf("%02X ", state[i]);
        // }
    }
}

int main() {
    /*
    unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x16, 0x47, 0x77, 0x11, 0x1e, 0x3c};
    unsigned char PT[128] = {0x66,0x61,0x64,0x73,0x66,0x61,0x64,0x73,0x61,0x64,0x66,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    unsigned char CT[128] = {0x78,0xE9,0x43,0x48,0xE5,0xE1,0x09,0x95,0x2B,0xFE,0x76,0xE8,0x4A,0x52,0x68,0xB4,0x68,0x88,0x67,0x2C,0x01,0x00,0x00,0x00,0x00,0xD4,0x00,0x60,0xFE,0x7F,0x00,0x00,0x50,0xB2,0xCF,0x0F,0x00,0x70,0x00,0x00,0x81,0xE4,0x4F,0x0B,0x01,0x00,0x00,0x00,0x68,0x88,0x67,0x2C,0x01,0x00,0x00,0x00,0x68,0x88,0x67,0x2C,0x01,0x00,0x00,0x00,0x00,0xD4,0x00,0x60,0xFE,0x7F,0x00,0x00,0x68,0x88,0x67,0x2C,0x01,0x00,0x00,0x00,0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x16,0x47,0x77,0x11,0x1E,0x3C,0xD0,0xB2,0xCF,0x0F,0x00,0x70,0x00,0x00,0xDE,0x00,0x4E,0x12,0xD9,0x95,0x37,0x4D,0xD0,0xB2,0xCF,0x0F,0x00,0x70,0x00,0x00,0x3A,0x35,0xB3,0x16,0x01,0x00,0x00,0x00};
    unsigned char enc[128];
    unsigned char dec[128];
    AES_ECB_Encrypt(PT,key,enc,128);
    printf("\n[ENC]\n");
    printState_AES(enc);

    AES_ECB_Decrypt(enc,key,dec,128);
    printf("\n[DEC]\n");
    printState_AES(dec);
    */

    uint8_t* out[32];// = {00,11,22,33,44,55,66,77,88,99,00,11,22,33,44,55,66,77,88,99,00,11,22,33,44,55,66,77,88,99,00,11};
    char out2[65];

    memset(&out, 18, 32);
    memset(&out2, 0, 65);

    // for(int i=0; i<32; i++) {
    //     out2[2*i] = (out[i])>>4;
    //     out2[2*i+1] = (out[i])&15;
    // }
    // printState3(out,40);
    // printState2(out2,40);
    printf("%x \n",out[0]);
    printf("%x \n",out[1]);
    printf("%d", 2000000/2);

    return 0;
}