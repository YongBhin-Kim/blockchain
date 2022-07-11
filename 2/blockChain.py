import ctypes
from hashlib import sha3_256
# import base58
import random
from ctypes import *

from numpy import block
my_sha3_256 = CDLL('./sha3ybtest.so') ## DLL을 읽어옴
# test_sha3_256 = CDLL('./')

# sha3_256 고속화
                # 160    , 256         , 256(160+864) , 256
blockChain = [] # blockID, current_hash, data         , prev_hash
def randData():
    data = ""
    for j in range(8192):
        data += format(j//16 * 10 + j%16,'040') # TxID 160bit -> hex
        data += hex(int(random.randrange(0, 1<<864)))[2:].ljust(216,'0') # 0~8192 : 8192*1024bit = 1MB = 2^23bit -> hex
    return data # hex
    
def make_genesis_block():
    blockID = format(0,'040') # blockID 0x00
    prev_hash = b'0'*20 # hash 160bit
    data = randData()
    # current_hash = bytes.fromhex(make_hash(blockID, prev_hash, data).hex()[24:]) # 25~64 총 40개만 가져옴
    current_hash = bytes.fromhex(make_hash(blockID, prev_hash, data).hex()[24:]) # 25~64 총 40개만 가져옴

    blockChain.append((blockID, current_hash, data, prev_hash))
    
def make_hash(blockID: str, prev_hash: bytes, data: str) -> bytes:
    # print("2. ",len(blockID + prev_hash.hex() + data), "\n\n")
    # print("2.1. ",len(blockID), "\n\n") # 1204 byte
    # print("2.2. ",len(prev_hash.hex()), "\n\n") # 1204 byte
    # print("2.3. ",len(data), "\n\n")
    # print("1. ",len((blockID + prev_hash.hex() + data)),"\n\n")
    # print("2. ", len((blockID + prev_hash.hex() + data).encode()),"\n\n")
    # return sha3_256((blockID + prev_hash.hex() + data).encode()).digest()
    # s = "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
    s = blockID + prev_hash.hex() + data
    ans3 = sha3_256(s.encode())
    # print("\nans3=",ans3.digest().hex(),"\n")
    ans = my_sha3_256.my_hash2(s.encode('utf-8'))
    tmp = ctypes.c_char_p(ans)
    # print("\n[3. ]\n", tmp)
    ans2 = (tmp.value).decode('utf-8')
    print("\n[4.] \n",ans2)
    
    return ans3.digest()
    


def add_block(i):
    global block75Data
    prev_hash = blockChain[-1][1]
    blockID = format((i//16)*10 + i%16,'040') # 160bit
    data = randData()
    if i==75:
        block75Data = data
    current_hash = bytes.fromhex(make_hash(blockID, prev_hash, data).hex()[24:]) # 25~64 총 40개만 가져옴
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def show_blockChain():
    for i, (blockID, current_hash, data, prev_hash) in enumerate(blockChain):
        # print(f'[블록 {i}]\nblock ID     : {blockID}\nprev hash    : {prev_hash.hex()}\ncurrent hash : {current_hash.hex()}\n')
        print(f'[block #{i}]\n prev hash    : 0X{prev_hash.hex()}\n current hash : 0X{current_hash.hex()}\n')
        # print(f'[block #{i}]\n prev hash    : {prev_hash.hex()}\n current hash : {current_hash}\n')

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
            print(f"블록 {i-1} 검증 실패. \n"
                  f"{last_current_hash.hex()} != \n{temp.hex()}")
            return False
        # if current_hash != (temp := make_hash(blockID,prev_hash,data)):
        if current_hash != (temp := bytes.fromhex(make_hash(blockID, prev_hash, data).hex()[24:])):
            print(f"블록 {i} 검증 실패.\n"
                  f"{current_hash.hex()} != \n{temp.hex()}")
            return False
    print("** 검증 성공 **\n")
    return True

make_genesis_block()
for i in range(1,101):
    add_block(i)
    
show_blockChain()
print()

##=========================================
##=============## verify ##================
##=========================================
# block75Data += '.'  # (여기를 주석 해제)
blockID = format(75//16*10 + 75%16,'040') # blockID : 75(=0x4b)
blockChain[75] = (blockID, bytes.fromhex(make_hash(blockID, blockChain[74][1], block75Data).hex()[24:]), block75Data, blockChain[74][1])
verify_blockChain()
##=========================================

# 1024*n bit = 1MB