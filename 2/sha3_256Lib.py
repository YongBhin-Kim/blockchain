# 1600 bit
# KECCAK_ROUND = 24 round
# define KECCAK_SHA3_256			256
# define KECCAK_SHA3_SUFFIX		    0x06
# define KECCAK_SHAKE_SUFFIX		0x1F
# keccakRate = 0
# keccakSuffix = 0
from copy import copy
import copy
from ctypes import memset
from pickletools import uint8

from numpy import block, unsignedinteger
global keccak_state
# keccak_state = [uint8(0) for _ in range(200)]
keccak_state = [0]*200
global SHA3_OK
SHA3_OK = 0
global end_offset, keccakCapacity, keccakSuffix, keccakRate
keccakRate = 0

global SHA3_SHAKE_NONE, SHA3_SHAKE_USE
SHA3_SHAKE_NONE = 0
SHA3_SHAKE_USE = 1


# [24][2]
keccakf_rndc = [ 
    [0x00000001, 0x00000000], [0x00008082, 0x00000000],
	[0x0000808a, 0x80000000], [0x80008000, 0x80000000],
	[0x0000808b, 0x00000000], [0x80000001, 0x00000000],
	[0x80008081, 0x80000000], [0x00008009, 0x80000000],
	[0x0000008a, 0x00000000], [0x00000088, 0x00000000],
	[0x80008009, 0x00000000], [0x8000000a, 0x00000000],

	[0x8000808b, 0x00000000], [0x0000008b, 0x80000000],
	[0x00008089, 0x80000000], [0x00008003, 0x80000000],
	[0x00008002, 0x80000000], [0x00000080, 0x80000000],
	[0x0000800a, 0x00000000], [0x8000000a, 0x80000000],
	[0x80008081, 0x80000000], [0x00008080, 0x80000000],
	[0x80000001, 0x00000000], [0x80008008, 0x80000000]]
keccakf_rotc = [1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44]
keccakf_piln = [10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1]
def ROL64(input, output, offset):
    shift = 0
    if offset==0:
        output[1]=input[1] 
        output[0]=input[0]
    elif offset<32:
        shift=offset 
        output[1] = (input[1] << shift) ^ (input[0] >> (32 - shift)) % 256
        output[0] = (input[0] << shift) ^ (input[1] >> (32 - shift)) % 256
    elif offset<64:
        shift = offset-32
        output[0] = ((input[0] << shift)%256) ^ ((input[1] >> (32 - shift)) % 256)
        output[1] = ((input[1] << shift)%256) ^ ((input[0] >> (32 - shift)) % 256)
    else:
        output[1]=input[1]
        output[0]=input[0]
def keccakf(state):
    t = [0]*2
    bc = [[0]*2 for i in range(5)]
    s = [[0]*2 for i in range(25)]
    
    for i in range(25):
        s[i][0] = ((state[i * 8 + 0])%(1<<32)) |((state[i * 8 + 1] << 8) %(1<<32)) | ((state[i * 8 + 2] << 16)%(1<<32)) | ((state[i * 8 + 3] << 24) % (1<<32))
        # print(hex(s[i][0]), end=' ')
        s[i][1] = ((state[i * 8 + 4])%(1<<32)) |((state[i * 8 + 5] << 8)%(1<<32)) | ((state[i * 8 + 6] << 16)%(1<<32)) | ((state[i * 8 + 7] << 24) % (1<<32))
        print(hex(s[i][1]), end=' ')
    
    
    for round in range(24):# KECCAK_ROUND
        ## Theta ##
        for i in range(5):
            bc[i][0] = s[i][0] ^ s[i + 5][0] ^ s[i + 10][0] ^ s[i + 15][0] ^ s[i + 20][0] 
            bc[i][1] = s[i][1] ^ s[i + 5][1] ^ s[i + 10][1] ^ s[i + 15][1] ^ s[i + 20][1] 
        for i in range(5):
            ROL64(bc[(i + 1) % 5], t, 1)

            t[0] ^= bc[(i + 4) % 5][0] 
            t[1] ^= bc[(i + 4) % 5][1] 

            for j in range(0,25,5):
                s[j + i][0] ^= t[0] % 256
                s[j + i][1] ^= t[1] % 256
        ## Rho & Pi ##
        t[0] = s[1][0] % 256
        t[1] = s[1][1] % 256
        for i in range(24): # KECCAK_ROUND
            j = keccakf_piln[i] 
            bc[0][0] = s[j][0] % 256
            bc[0][1] = s[j][1] % 256
            ROL64(t, s[j], keccakf_rotc[i])
            t[0] = bc[0][0]
            t[1] = bc[0][1]
            
        ## Chi ##
        for j in range(0,25,5):
            for i in range(5):
                bc[i][0] = s[j+i][0] % 256
                bc[i][1] = s[j+i][1] % 256
            for i in range(5):
                s[j + i][0] ^= (~bc[(i + 1) % 5][0]) & bc[(i + 2) % 5][0]
                s[j + i][1] ^= (~bc[(i + 1) % 5][1]) & bc[(i + 2) % 5][1]
                
        ## Iota ##
        s[0][0] ^= keccakf_rndc[round][0] % 256
        s[0][1] ^= keccakf_rndc[round][1] % 256
    for i in range(25):
        state[i * 8 + 0] = s[i][0]
        state[i * 8 + 1] = s[i][0] >> 8
        state[i * 8 + 2] = s[i][0] >> 16
        state[i * 8 + 3] = s[i][0] >> 24
        state[i * 8 + 4] = s[i][1]
        state[i * 8 + 5] = s[i][1] >> 8
        state[i * 8 + 6] = s[i][1] >> 16
        state[i * 8 + 7] = s[i][1] >> 24

def keccak_absorb(input, inLen, rate, capacity):
    global keccak_state
    global SHA3_OK
    global end_offset
    buf = input # 163 163 163
    # buf = copy.deepcopy(input)
    iLen = inLen # 200
    rateInBytes = rate // 8
    blockSize = 0
    tmp = 0
    i = 0
    if (rate + capacity) != 1600: # KECCAK_SPONGE_BIT = 1600
        return 1 # SHA3_PARAMETER_ERROR
    if (((rate % 8) != 0) or (rate < 1)):
        return 1 # SHA3_PARAMETER_ERROR
    
    # 07-05 01:15 여기부터.
    # print("end offset = ? ", end_offset)
    while iLen > 0:
        # print("iLen = ", iLen)
        if ((end_offset != 0) and (end_offset < rateInBytes)):
            blockSize = min((iLen + end_offset), rateInBytes)
            for i in range(end_offset, blockSize):
                keccak_state[i] = (keccak_state[i]) ^ (buf[i - end_offset])
            for t in range(len(buf)):######
                buf[t] = (buf[t] + blockSize - end_offset) % 256######
            iLen -= (blockSize - end_offset) 
            
        else:
            blockSize = min(iLen, rateInBytes) # 136 64
            tmp += blockSize
            for i in range(blockSize):
                keccak_state[i] = (buf[i] % 256) ^ (keccak_state[i] % 256)
            # print("7. ", buf)
            for t in range(len(buf)-tmp, len(buf)):
                # buf[t] = (buf[t]%256 + blockSize) % 256
                buf[t]=0
            # buf[len(buf)-blockSize]=0 # 64
            # buf[len(buf)-blockSize+1]=208
            # buf[len(buf)-blockSize+2]=8
            # buf[len(buf)-blockSize+3]=0
            # buf[len(buf)-blockSize+4]=1
            # print("8. ")
            # for i in range(200):
                # print(buf[i], end=' ')
            # print("\n")
            # print(keccak_state)
            # print(buf)
            iLen -= blockSize
            
        if blockSize == rateInBytes:
            keccakf(keccak_state)
            blockSize = 0
            
        end_offset = blockSize
    return SHA3_OK

def keccak_squeeze(output, outLen, rate, suffix):
    global end_offset
    
    buf = output
    oLen = outLen
    rateInBytes = rate // 8
    blockSize = end_offset
    i = 0
    keccak_state[blockSize] ^= suffix
    
    if (((suffix & 0x80) != 0) and (blockSize == (rateInBytes - 1))):
        keccakf(keccak_state)
    keccak_state[rateInBytes - 1] ^= 0x80
    
    keccakf(keccak_state)
    
    while (oLen > 0):
        blockSize = min(oLen, rateInBytes)
        for i in range(blockSize):
            buf[i] = keccak_state[i] % 256
        for t in range(len(buf)):######
            buf[t] = (buf[t] + blockSize) % 256######
            # buf[t] = 0
        oLen -= blockSize
        if oLen > 0:
            keccakf(keccak_state)
    return SHA3_OK

def sha3_init(bitSize, useSHAKE):
    global end_offset, keccakRate, keccakCapacity, keccakSuffix
    keccakCapacity = bitSize * 2
    # print("2. ", keccakRate)
    keccakRate = 1600 - keccakCapacity # 1088, KECCAK_SPONGE_BIT = 1600
    
    if (useSHAKE):
        keccakSuffix = 0x1F # KECCAK_SHAKE_SUFFIX
    else:
        print("3. NoShake")
        keccakSuffix = 0x06 # KECCAK_SHA3_SUFFIX
    # memset(keccak_state, 0x00, 200) # KECCAK_STATE_SIZE = 200
    keccak_state = [0x00]*200 # ?
    end_offset = 0
    
def sha3_update(input, inLen):
    global keccakRate, keccakCapacity
    return keccak_absorb(input, inLen, keccakRate, keccakCapacity)

def sha3_final(output, outLen):
    global keccakRate, keccakSuffix, keccak_state
    ret = keccak_squeeze(output, outLen, keccakRate, keccakSuffix)
    keccakRate = 0
    keccakCapacity = 0
    keccakSuffix = 0
    
    # memset(keccak_state, 0x00, 200) # KECCAK_STATE_SIZE = 200
    keccak_state = [0x00]*200
    return ret

def sha3_hash(output, outLen, input, inLen, bitSize, useSHAKE):
    ret = 0
    if useSHAKE == SHA3_SHAKE_USE:
        if (bitSize != 128) and (bitSize != 256): # KECCAK_SHAKE128 KECCAK_SHAKE256
            return 1 # SHA3_PARAMETER_ERROR
        sha3_init(bitSize, SHA3_SHAKE_USE)
    else:
        if ((bitSize != 224) and (bitSize != 256) and (bitSize != 384) and (bitSize != 512)):
            return 1 # SHA3_PARAMETER_ERROR
        if ((bitSize // 8) != outLen):
            return 1 # SHA3_PARAMETER_ERROR
        sha3_init(bitSize, SHA3_SHAKE_NONE) # 256, 0
    sha3_update(input, inLen)
    ret = sha3_final(output, outLen)
    return ret


def main():
    output = [0]*512
    input  = [0xA3]*200
    out_length = 0
    in_length = 200
    hash_bit = 0
    SHAKE = 0
    
    # memset(input, 0xA3, 200)
    
    
    print('* SHA-3 test *\n\n')
    print('test message : A3(x200)\n\n')
    
    # /* non-SHAKE test */
    SHAKE = 0
    
    # /* SHA3-256 test */
    out_length = 256 // 8
    hash_bit = 256
    result = sha3_hash(output, out_length, input, in_length, hash_bit, SHAKE)
    print("SHA3-256 test\n")
    print("hash : ")
    for i in range(out_length):
        print(hex(output[i]), end=' ')
    
    # print(hex(output[0]))
    print("\n\n")
    
    '''
    # /* SHAKE test */
    SHAKE = 1
    # /* SHAKE128 test */
    out_length = 512
    hash_bit = 128
    result = sha3_hash(output, out_length, input, in_length, hash_bit, SHAKE)
    
    print("SHAKE256 test\n")
    print("output : 512bytes\n")
    print("hash : ")
    for i in range(out_length):
        print("", hex(output[i]))
    print("\n\n")
    
    # /* SHAKE256 test */
    out_length = 512
    hash_bit = 256
    result = sha3_hash(output, out_length, input, in_length, hash_bit, SHAKE)
    
    print("SHAKE256 test\n")
    print("output : 512bytes\n")
    print("hash : ")
    for i in range(out_length):
        print("", hex(output[i]))
    print("\n\n")
    '''
    
if __name__ == "__main__":
    main()