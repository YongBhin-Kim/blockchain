# ================================================================================== 
#                       2022 암호분석경진대회 2번문제 - DaBakSal(DBS)
# ================================================================================== 

'''
[Information]
- BlockID : [hex string]    160 bit     (ex) 000000000000000000000000000000000000000c

- Hash    : [bytes]         160 bit     (ex) d42db5c0621e588b474bb1698a941484a6e23370
    - previous hash, currnet hash
    
- Data    : [hex string]    1MB         (= 1048576 bytes, length = 2097152)
    - TxID + transaction                (1MB = 1024 bit * 8192)
        - TxID         (160 bit)
        - Transaction  (864 bit) - random number

- Block(n)은 Block(n-1) 전체에 대한 SHA3_256의 하위 160bit 해시값


[Use]
*** List 
    ** blockChain 
        * [Block ID, current hash, data, previous hash]의 형식으로 구성된 list

*** Function
    ** randData                             : Generate Data 
        * Insert 160bit TxID(0x01, 0x02, ...., 0x64), padding zero
        * Fill 864bit random number, padding zero

    ** make_genesis_block                   : Create Genesis Block
        * Insert 160bit Block ID(0x00)
        * Previous hash : 160bit 0x00
        * Current hash  : 
    ** make_hash                            : Hash function
        * Hashing with SHA3_256 in a C environment
        * Return lower 160 bits

    ** add_block                            : Add Blocks to BlockChain
        * BlockChain List [Block ID, current hash, data, previous hash] 
            * BlockChain[0] : Add 'current Block ID' to blockchain list     (to geneate a 160-bit hash value)
            * BlockChain[1] : Add 'current hash'  to blockchain list        (to verify a 160-bit hash value)
            * BlockChain[2] : Add 'current data'  to blockchain list        (to geneate a 160-bit hash value)
            * BlockChain[3] : Add 'previous'  to blockchain list            (to geneate a 160-bit hash value)
            
    ** verify_blockChain                    : Verify Block Chain
        * Validate by comparing the "previous_hash" value of the current block with "current_hash" value of the previous block
        
                
*** Test Code
    ** Show block chain
        * Use function show_blockchain()
        
    ** Insert Error
        * Change the block 50's 100th index value to .(point)
    
    ** Verification
        * Use function verify_blockChain()
'''


'''
[import]

*** base58
    * base58 encoding

*** random
    * Imported random to create random number

*** ctypes
    * Imported ctypes to perform hash in a fast C environment
    
'''

# import base58
import random

import ctypes
from ctypes import *
Sha3_256_DBS = CDLL('./Sha3_256_DBS.so')


blockChain = [] 

def randData():
    data = ""
    for j in range(8192):
        # TxID : 160bit
        data += hex(j)[2:].rjust(40,'0') 
        
        # Transaction value : Fill 864bit random number, padding zero
        data += hex(int(random.randrange(0, 1<<864)))[2:].rjust(216,'0')
    return data
    
def make_genesis_block():
    blockID = hex(0)[2:].rjust(40,'0')
    current_hash = bytes.fromhex(hex(0)[2:].rjust(40,'0'))
    data = randData()
    prev_hash = bytes.fromhex(hex(0)[2:].rjust(40,'0'))
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def make_hash(prev_blockID: str, prev_hash: bytes, prev_data: str) -> bytes:
    # Length of Total previous block is 1048616 (bytes)
    prev_block = prev_blockID.encode() + prev_hash + prev_data.encode() 
    char_pointer = ctypes.c_char_p(prev_block)
    
    # Hashing with SHA3_256 in a C environment
    Sha3_256_DBS.hashFunc(char_pointer)
    
    # Return lower 160 bits
    return bytes.fromhex((char_pointer.value[12:32]).hex())

def add_block(i):
    blockID = hex(i)[2:].rjust(40,'0')
    data = randData()
        
    prev_hash = blockChain[-1][1]
    prev_blockID = blockChain[-1][0]
    prev_data    = blockChain[-1][2]
        
        
    current_hash = make_hash(prev_blockID, prev_hash, prev_data)
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def show_blockChain():
    for i, (blockID, current_hash, data, prev_hash) in enumerate(blockChain):
        print(f'[Block #{i}]\n previous hash    : (0x){prev_hash.hex()}\n current hash     : (0x){current_hash.hex()}\n')

def verify_blockChain():
    for i in range(2, len(blockChain)):
        blockID, current_hash, data, prev_hash = blockChain[i]
        llast_blockID, llast_current_hash, llast_data, llast_prev_hash= blockChain[i-2]
        last_blockID, last_current_hash, last_data, last_prev_hash = blockChain[i-1]
        if prev_hash != last_current_hash:
            print(f"1. Previous hash value of Block #{i} != Current hash value of Block #{i-1} \n"
                f"{prev_hash.hex()} != \n{last_current_hash.hex()} \n\n**Verification Failed**")
            return False
        
        if last_current_hash != (temp := make_hash(llast_blockID, last_prev_hash, llast_data)):
            print(f"2. Block #{i-1} Verification Failed. \n"
                f"{last_current_hash.hex()} != \n{temp.hex()}")
            return False
        if current_hash != (temp := make_hash(last_blockID,prev_hash,last_data)):
            print(f"3. Block {i} Verification Failed.\n"
                f"{current_hash.hex()} != \n{temp.hex()}")
            return False
    print("** 검증 성공 **\n")
    return True


#   [Create genesis block]
make_genesis_block()

#   [Append block from 1 to 100]
for i in range(1,100):
    add_block(i)
    
#   [Show block chain]
show_blockChain()



# ========================================= 
#                Test Code
# =========================================

#   [Error injection]
'''
    If the error_mode value is 1, the error is injected
'''
error_mode = 0
# error_mode = 1

if error_mode == 1:
    block50ID   = blockChain[50][0]; block49Hash = blockChain[49][1]; block50Data = blockChain[50][2]
    block49ID   = blockChain[49][0];                                  block49Data = blockChain[49][2]

    # Change the block 50's 100th index value to .(point)
    errorhash = make_hash(block49ID, block49Hash, block49Data[:99] + '.' + block49Data[100:]) 
    
    blockChain[50] = (block50ID, errorhash, block50Data, block49Hash)


#  [Verification]
'''
    Function verify_blockChain() is verify block chain use hash value
'''
verify_blockChain()