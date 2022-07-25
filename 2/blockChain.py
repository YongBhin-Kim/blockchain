import ctypes
from hashlib import sha3_256
# import base58
import random
from ctypes import *

from numpy import block
my_sha3_256 = CDLL('./sha3ybtest2.so') ## DLL을 읽어옴
# test_sha3_256 = CDLL('./')

# sha3_256 고속화
                # 160    , 256         , 256(160+864) , 256
blockChain = [] # blockID, current_hash, data         , prev_hash
def randData():
    data = ""
    for j in range(8192):
        data += format(j//16 * 10 + j%16,'040') # TxID 160bit -> hex
        data += hex(int(random.randrange(0, 1<<864)))[2:].ljust(216,'0') # 0~8192 : 8192*1024bit = 1MB = 2^23bit -> hex # 0x 제외하고 가져옴
    return data # hex
    
def make_genesis_block():
    blockID = format(0,'040') # blockID 0x00
    prev_hash = b'0'*20 # hash 160bit
    data = randData()
    # current_hash = bytes.fromhex(make_hash(blockID, prev_hash, data).hex()[24:]) # 25~64 총 40개만 가져옴
    current_hash = make_hash(blockID, prev_hash, data)
    print("genesis hash = ", len(current_hash))
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def make_hash(blockID: str, prev_hash: bytes, data: str) -> bytes:
    s = "0123456789012345678901234567890123456789" # 임시로 설정한 160비트
    ''' s = blockID + prev_hash.hex() + data''' # 2097232
    s2 = ctypes.c_wchar_p(s)
    
    #============ C에 넘기기 ===========
    
    my_sha3_256.my_hash2(s2) # s2.value length = 2097232
    print("len of s2.value", s2.value[:100])
    return bytes.fromhex(s2.value[24:64]) # 25~64 총 40개만 가져옴
    
    '''
    s3 = ctypes.c_wchar_p(my_sha3_256.my_hash3(s2))
    print('s3 = ', s3.value)
    return bytes.fromhex(s3.value[24:])
    '''
    


def add_block(i):
    global block75Data
    prev_hash = blockChain[-1][1]
    blockID = format((i//16)*10 + i%16,'040') # 160bit
    print("blockID = ", blockID)
    print("prev_hash = ", len(prev_hash))
    data = randData()
    print("len data = ", len(data))
    if i==75:
        block75Data = data
    current_hash = make_hash(blockID, prev_hash, data) # 25~64 총 40개만 가져옴
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def show_blockChain():
    for i, (blockID, current_hash, data, prev_hash) in enumerate(blockChain):
        # print(f'[블록 {i}]\nblock ID     : {blockID}\nprev hash    : {prev_hash.hex()}\ncurrent hash : {current_hash.hex()}\n')
        print(f'[block #{i}]\n prev hash    : 0X{prev_hash.hex()}\n current hash : 0X{current_hash.hex()}\n')
        # print(f'[block #{i}]\n prev hash    : 0X{prev_hash.hex()}\n current hash : 0X{current_hash.hex()}\n')

def verify_blockChain(): # 고속화
    for i in range(1, len(blockChain)):
        blockID, current_hash, data, prev_hash = blockChain[i]
        last_blockID, last_current_hash, last_data, last_prev_hash = blockChain[i-1]
        if prev_hash != last_current_hash:
            print(f"블록 {i} 이전 해시값 != 블록 {i-1} 현재 해시값 \n"
                  f"{prev_hash.hex()} != \n{last_current_hash.hex()} \n\n**검증 실패**")
            return False
          
        # if last_current_hash != (temp := make_hash(last_blockID, last_prev_hash, last_data)):
        if last_current_hash != (temp := bytes.fromhex(make_hash(last_blockID, last_prev_hash, last_data).hex()[24:])):
            # print(f"블록 {i-1} 검증 실패. \n"
                #   f"{last_current_hash} != \n{temp}")
            # '''
            print(f"블록 {i-1} 검증 실패. \n"
                  f"{last_current_hash.hex()} != \n{temp.hex()}")
            # '''
            return False
        # if current_hash != (temp := make_hash(blockID,prev_hash,data)):
        if current_hash != (temp := bytes.fromhex(make_hash(blockID, prev_hash, data)[24:])):
            print(f"블록 {i} 검증 실패.\n"
                  f"{current_hash.hex()} != \n{temp.hex()}")
            return False
    print("** 검증 성공 **\n")
    return True

make_genesis_block()
for i in range(1,101):
    add_block(i)
    print("[",i,"]","번째")
    
print()

##=========================================
##=============## verify ##================
##=========================================
# block75Data += '.'  # (여기를 주석 해제)
blockID = format(75//16*10 + 75%16,'040') # blockID : 75(=0x4b)
blockChain[75] = (blockID, make_hash(blockID, blockChain[74][1], block75Data), block75Data, blockChain[74][1])
verify_blockChain()
##=========================================

# 1024*n bit = 1MB