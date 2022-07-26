import ctypes
from hashlib import sha3_256
# import base58
import random
from ctypes import *

from numpy import block
my_sha3_256 = CDLL('./sha3ybtest2.so') ## DLL을 읽어옴

'''
- BlockID : [hex string]    160 bit     (ex) 000000000000000000000000000000000000000c

- Hash    : [bytes]         160 bit     (ex) d42db5c0621e588b474bb1698a941484a6e23370
    - previous hash, currnet hash
    
- Data    : [hex string]    1MB         (= 1048576 bytes, length = 2097152)
    - TxID + transaction                (1MB = 1024 bit * 8192)
        - TxID         (160 bit)
        - Transaction  (864 bit) - random number

        
- Block(n)은 Block(n-1) 전체에 대한 SHA3_256의 하위 160bit 해시값

*** List 
    ** blockChain 
        * [Block ID, current hash, data, previous hash]의 형식으로 구성된 list

*** Function
    ** randData                             : Generate Data 
        * Insert 160bit TxID(0x01, 0x02, ...., 0x64), padding zero
        * Fill 864bit random number, padding zero

    **
        *
    ** verify_blockChain                    : Verify Block Chain
        *        
    ** make_genesis_block                   : Create Genesis Block
        * Insert 160bit Block ID(0x00)
        * Previous hash : 160bit 0x00
        * Current hash  : 
        
*** Test Code
    ** Insert Error
        * 
    
    ** Verification
        * Use function verify_blockChain()
'''

blockChain = [] 

def randData():
    data = ""
    for j in range(8192):
        data += hex(j)[2:].rjust(40,'0') # TxID : 160bit
        data += hex(int(random.randrange(0, 1<<864)))[2:].rjust(216,'0') # 0~8192 : 8192*1024bit = 1MB = 2^23bit -> hex # 0x 제외하고 가져옴
    return data
    
def make_genesis_block():
    blockID = hex(0)[2:].rjust(40,'0')
    current_hash = bytes.fromhex(hex(0)[2:].rjust(40,'0'))
    data = randData()
    prev_hash = bytes.fromhex(hex(0)[2:].rjust(40,'0'))
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def make_hash(prev_blockID: str, prev_hash: bytes, prev_data: str) -> bytes:
    s = prev_blockID.encode() + prev_hash + prev_data.encode() # 1048616
    s2 = ctypes.c_char_p(s)
    # ============ C에 넘기기 ===========
    my_sha3_256.my_hash2(s2) # s2.value length = 2097232
    return bytes.fromhex((s2.value[12:32]).hex()) # 총 40개의 알파벳을 가져옴

def add_block(i):
    '''global block75Data'''
    blockID = hex(i)[2:].rjust(40,'0')
    data = randData()
    '''if i==75:
        block75Data = data'''
        
    prev_hash = blockChain[-1][1]
    prev_blockID = blockChain[-1][0] # hex(i-1)[2:].rjust(40,'0')  # ( int("0x" + blockID[38:], 16) ) # * [Block ID, current hash, data, previous hash]의 형식으로 구성된 list
    prev_data    = blockChain[-1][2]
        
        
    current_hash = make_hash(prev_blockID, prev_hash, prev_data)
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def show_blockChain():
    for i, (blockID, current_hash, data, prev_hash) in enumerate(blockChain):
        print(f'[Block #{i}]\n previous hash    : (0x){prev_hash.hex()}\n current hash     : (0x){current_hash.hex()}\n')

def verify_blockChain(): # 고속화
    for i in range(2, len(blockChain)):
        blockID, current_hash, data, prev_hash = blockChain[i]
        llast_blockID, llast_current_hash, llast_data, llast_prev_hash= blockChain[i-2]
        last_blockID, last_current_hash, last_data, last_prev_hash = blockChain[i-1]
        # else:
        if prev_hash != last_current_hash:
            print(f"1. 블록 {i} 이전 해시값 != 블록 {i-1} 현재 해시값 \n"
                f"{prev_hash.hex()} != \n{last_current_hash.hex()} \n\n**검증 실패**")
            return False
        
        if last_current_hash != (temp := make_hash(llast_blockID, last_prev_hash, llast_data)):
            print(f"2. 블록 {i-1} 검증 실패. \n"
                f"{last_current_hash.hex()} != \n{temp.hex()}")
            return False
        if current_hash != (temp := make_hash(last_blockID,prev_hash,last_data)):
            print(f"3. 블록 {i} 검증 실패.\n"
                f"{current_hash.hex()} != \n{temp.hex()}")
            return False
    print("** 검증 성공 **\n")
    return True

make_genesis_block()
for i in range(1,100):
    add_block(i)
    
show_blockChain()
print()

# ========================================= 
#                Test Code
# =========================================

#   [Insert Error] 
# If error_mode = 1 then insert Error
error_mode = 1
# error_mode = 0

if error_mode == 1:
    block50ID   = blockChain[50][0]; block49Hash = blockChain[49][1]; block50Data = blockChain[50][2]
    block49ID   = blockChain[49][0];                                  block49Data = blockChain[49][2]

    errorhash = make_hash(block49ID, block49Hash, block49Data[:99] + '.' + block49Data[100:])  # Block ID 50의 data의 100번째 index의 값을 "." 으로 교체 (오류 주입)
    
    blockChain[50] = (block50ID, errorhash, block50Data, block49Hash)


#  [Verification]
verify_blockChain()