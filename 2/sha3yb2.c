#include "sha3yb.h"

#define KECCAK_SPONGE_BIT       1600
#define KECCAK_ROUND            24
#define KECCAK_STATE_SIZE       200

#define KECCAK_SHA3_224         224
#define KECCAK_SHA3_256         256
#define KECCAK_SHA3_384         384
#define KECCAK_SHA3_512         512
#define KECCAK_SHAKE128         128
#define KECCAK_SHAKE256         256

#define KECCAK_SHA3_SUFFIX      0x06
#define KECCAK_SHAKE_SUFFIX     0x1F
#define messize                 1048616 // 1048616

typedef unsigned long long BYTE;

// 마지막 NULL을 넣어둠
// char message[messize * 4 + 1] = { 0, };
uint8_t input1[1048617] = { 0, };
uint8_t input2[1048617] = { 0, };
// uint8_t input2[200] = { 0, };

typedef enum
{
    SHA3_OK = 0,
    SHA3_PARAMETER_ERROR = 1,
} SHA3_RETRUN;


typedef enum
{
    SHA3_SHAKE_NONE = 0,
    SHA3_SHAKE_USE = 1,
} SHA3_USE_SHAKE;



static unsigned int keccakRate = 0;
static unsigned int keccakCapacity = 0;
static unsigned int keccakSuffix = 0;

static uint8_t keccak_state[KECCAK_STATE_SIZE] = { 0x00, };
static int end_offset;

static const uint32_t keccakf_rndc[KECCAK_ROUND][2] =
{
    {0x00000001, 0x00000000}, {0x00008082, 0x00000000},
    {0x0000808a, 0x80000000}, {0x80008000, 0x80000000},
    {0x0000808b, 0x00000000}, {0x80000001, 0x00000000},
    {0x80008081, 0x80000000}, {0x00008009, 0x80000000},
    {0x0000008a, 0x00000000}, {0x00000088, 0x00000000},
    {0x80008009, 0x00000000}, {0x8000000a, 0x00000000},

    {0x8000808b, 0x00000000}, {0x0000008b, 0x80000000},
    {0x00008089, 0x80000000}, {0x00008003, 0x80000000},
    {0x00008002, 0x80000000}, {0x00000080, 0x80000000},
    {0x0000800a, 0x00000000}, {0x8000000a, 0x80000000},
    {0x80008081, 0x80000000}, {0x00008080, 0x80000000},
    {0x80000001, 0x00000000}, {0x80008008, 0x80000000}
};

static const unsigned keccakf_rotc[KECCAK_ROUND] =
{
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[KECCAK_ROUND] =
{
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};


void ROL64(uint32_t* in, uint32_t* out, int offset)
{
    int shift = 0;

    if (offset == 0)
    {
        out[1] = in[1];
        out[0] = in[0];
    }
    else if (offset < 32)
    {
        shift = offset;

        out[1] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
        out[0] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
    }
    else if (offset < 64)
    {
        shift = offset - 32;

        out[1] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
        out[0] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
    }
    else
    {
        out[1] = in[1];
        out[0] = in[0];
    }
}


void keccakf(uint8_t* state)
{
    uint32_t t[2], bc[5][2], s[25][2] = { 0x00, };
    int i, j, round;

    for (i = 0; i < 25; i++)
    {
        s[i][0] = (uint32_t)(state[i * 8 + 0]) |
            (uint32_t)(state[i * 8 + 1] << 8) |
            (uint32_t)(state[i * 8 + 2] << 16) |
            (uint32_t)(state[i * 8 + 3] << 24);

        s[i][1] = (uint32_t)(state[i * 8 + 4]) |
            (uint32_t)(state[i * 8 + 5] << 8) |
            (uint32_t)(state[i * 8 + 6] << 16) |
            (uint32_t)(state[i * 8 + 7] << 24);
    }

    for (round = 0; round < KECCAK_ROUND; round++)
    {
        /* Theta */
        for (i = 0; i < 5; i++)
        {
            bc[i][0] = s[i][0] ^ s[i + 5][0] ^ s[i + 10][0] ^ s[i + 15][0] ^ s[i + 20][0];
            bc[i][1] = s[i][1] ^ s[i + 5][1] ^ s[i + 10][1] ^ s[i + 15][1] ^ s[i + 20][1];
        }

        for (i = 0; i < 5; i++)
        {
            ROL64(bc[(i + 1) % 5], t, 1);

            t[0] ^= bc[(i + 4) % 5][0];
            t[1] ^= bc[(i + 4) % 5][1];

            for (j = 0; j < 25; j += 5)
            {
                s[j + i][0] ^= t[0];
                s[j + i][1] ^= t[1];
            }
        }

        /* Rho & Pi */
        t[0] = s[1][0];
        t[1] = s[1][1];

        for (i = 0; i < KECCAK_ROUND; i++)
        {
            j = keccakf_piln[i];

            bc[0][0] = s[j][0];
            bc[0][1] = s[j][1];

            ROL64(t, s[j], keccakf_rotc[i]);

            t[0] = bc[0][0];
            t[1] = bc[0][1];
        }

        /* Chi */
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++)
            {
                bc[i][0] = s[j + i][0];
                bc[i][1] = s[j + i][1];
            }

            for (i = 0; i < 5; i++)
            {
                s[j + i][0] ^= (~bc[(i + 1) % 5][0]) & bc[(i + 2) % 5][0];
                s[j + i][1] ^= (~bc[(i + 1) % 5][1]) & bc[(i + 2) % 5][1];
            }
        }

        /* Iota */
        s[0][0] ^= keccakf_rndc[round][0];
        s[0][1] ^= keccakf_rndc[round][1];
    }

    for (i = 0; i < 25; i++)
    {
        state[i * 8 + 0] = (uint8_t)(s[i][0]);
        state[i * 8 + 1] = (uint8_t)(s[i][0] >> 8);
        state[i * 8 + 2] = (uint8_t)(s[i][0] >> 16);
        state[i * 8 + 3] = (uint8_t)(s[i][0] >> 24);
        state[i * 8 + 4] = (uint8_t)(s[i][1]);
        state[i * 8 + 5] = (uint8_t)(s[i][1] >> 8);
        state[i * 8 + 6] = (uint8_t)(s[i][1] >> 16);
        state[i * 8 + 7] = (uint8_t)(s[i][1] >> 24);
    }
}


int keccak_absorb(uint8_t* input, int inLen, int rate, int capacity)
{
    uint8_t* buf = input;
    int iLen = inLen;
    int rateInBytes = rate / 8;
    int blockSize = 0;
    int i = 0;

    if ((rate + capacity) != KECCAK_SPONGE_BIT)
        return SHA3_PARAMETER_ERROR;

    if (((rate % 8) != 0) || (rate < 1))
        return SHA3_PARAMETER_ERROR;

    while (iLen > 0)
    {
        if ((end_offset != 0) && (end_offset < rateInBytes))
        {
            blockSize = (((iLen + end_offset) < rateInBytes) ? (iLen + end_offset) : rateInBytes);

            for (i = end_offset; i < blockSize; i++)
                keccak_state[i] ^= buf[i - end_offset];

            buf += blockSize - end_offset;
            iLen -= blockSize - end_offset;
        }
        else
        {

            blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);

            for (i = 0; i < blockSize; i++)
                keccak_state[i] ^= buf[i];

            buf += blockSize;
            iLen -= blockSize;
        }

        if (blockSize == rateInBytes)
        {
            keccakf(keccak_state);
            blockSize = 0;
        }
        end_offset = blockSize;
    }

    return SHA3_OK;
}


int keccak_squeeze(uint8_t* output, int outLen, int rate, int suffix)
{
    uint8_t* buf = output;
    int oLen = outLen;
    int rateInBytes = rate / 8;
    int blockSize = end_offset;
    int i = 0;

    keccak_state[blockSize] ^= suffix;

    if (((suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
        keccakf(keccak_state);

    keccak_state[rateInBytes - 1] ^= 0x80;

    keccakf(keccak_state);

    while (oLen > 0)
    {
        blockSize = ((oLen < rateInBytes) ? oLen : rateInBytes);
        for (i = 0; i < blockSize; i++)
            buf[i] = keccak_state[i];
        buf += blockSize;
        oLen -= blockSize;

        if (oLen > 0)
            keccakf(keccak_state);
    }

    return SHA3_OK;
}


void sha3_init(int bitSize, int useSHAKE)
{
    keccakCapacity = bitSize * 2;
    keccakRate = KECCAK_SPONGE_BIT - keccakCapacity;

    if (useSHAKE)
        keccakSuffix = KECCAK_SHAKE_SUFFIX;
    else
        keccakSuffix = KECCAK_SHA3_SUFFIX;

    memset(keccak_state, 0x00, KECCAK_STATE_SIZE);

    end_offset = 0;
}


int sha3_update(uint8_t* input, int inLen)
{
    return keccak_absorb(input, inLen, keccakRate, keccakCapacity);
}


int sha3_final(uint8_t* output, int outLen)
{
    int ret = 0;

    ret = keccak_squeeze(output, outLen, keccakRate, keccakSuffix);

    keccakRate = 0;
    keccakCapacity = 0;
    keccakSuffix = 0;

    memset(keccak_state, 0x00, KECCAK_STATE_SIZE);

    return ret;
}


int sha3_hash(uint8_t* output, int outLen, uint8_t* input, int inLen, int bitSize, int useSHAKE)
{
    int ret = 0;

    if (useSHAKE == SHA3_SHAKE_USE)
    {
        if ((bitSize != KECCAK_SHAKE128) && (bitSize != KECCAK_SHAKE256))
            return SHA3_PARAMETER_ERROR;

        sha3_init(bitSize, SHA3_SHAKE_USE);
    }
    else
    {
        if ((bitSize != KECCAK_SHA3_224) && (bitSize != KECCAK_SHA3_256) &&
            (bitSize != KECCAK_SHA3_384) && (bitSize != KECCAK_SHA3_512))
            return SHA3_PARAMETER_ERROR;

        if ((bitSize / 8) != outLen)
            return SHA3_PARAMETER_ERROR;

        sha3_init(bitSize, SHA3_SHAKE_NONE);
    }

    sha3_update(input, inLen);

    ret = sha3_final(output, outLen);
    return ret;
}

uint8_t ascii_to_hex(const char* str, size_t size, uint8_t* hex)
{
    uint8_t i, h, high, low;
    for (h = 0, i = 0; i < size; i += 2, ++h) {
        high = (str[i] > '9') ? str[i] - 'A' + 10 : str[i] - '0';
        low = (str[i + 1] > '9') ? str[i + 1] - 'A' + 10 : str[i + 1] - '0';
        hex[h] = (high << 4) | low;
        }
    return h;
}
void printState(uint8_t* state, size_t size) {
    printf("\n [Hello, World1]\n");
    for(int i=0; i<1000000; i++)
        printf("%02X ", state[i]);
}

void printState2(char* state, size_t size) {
    printf("\n[C] : 받은 s값 출력, char 자료형\n");
    for(int i=0; i<300; i++) {
        // if (i % 4 != 0) {
        printf("%d ", state[i]);
        // }
    }
}
void printState3(uint8_t* state, size_t size) {
    printf("\n[C]\n");// : 받은 s값 출력, uint8_t 자료형\n");
    for(int i=0; i<size; i++) {
        // if (i % 4 != 0) {
        printf("%02X ", state[i]);
        // }
    }
}

uint8_t* tmp;
uint8_t out[65] = { 0, };       // 64 byte
uint8_t input3[messize];

void my_hash2(uint8_t* message) {
    /*
    for (int k=0; k<messize; k++) {
        printf("[%d] ",message[k]);
    }
    printf("[C1] : \n");
   */
    
    for (int k=0; k<messize; k++) {
        input3[k]=message[k];
    }

    int out_length = 256 / 8;   //byte size -> 64 byte
    int in_length = 200;
    int hash_bit = 256;         //256 bit
    int SHAKE = 0;              //0 or 1
    int i, result;

    result = sha3_hash(out, out_length, input3, in_length, hash_bit, SHAKE);
    for (int k=0; k<64; k++) {
        message[k]=out[k];
        if (out[k]==0) {
            message[k]=0x01;
        }
    }
    message[33]=0xff;

    /*
    printState3(out,32);
    printState3(message,32);

    printState3(message,32);
    */
    
}

int main()
{
    int out_length = 0;

    uint8_t* result;
    char* result2;

    printf("\n\n");
    
    return 0;

}