from hashlib import sha3_256
import random
# sha3_256 고속화
                # 160    , 256         , 256(160+864) , 256
blockChain = [] # blockID, current_hash, data         , prev_hash
def randData():
    for j in range(8192):
        data = format(j,'0160') # TxID
        data += format(random.randrange(0, 1<<864), '0864') # 0~8192 : 8192*1024bit = 1MB = 2^23bit
    return data
    
    
def make_genesis_block():
    blockID = format(0,'0160') # blockID 0x00
    prev_hash = b'0'*160
    data = randData()
    current_hash = bytes.fromhex(make_hash(blockID, prev_hash, data).hex()[24:]) # 25~64 총 40개만 가져옴

    blockChain.append((blockID, current_hash, data, prev_hash))
    
def make_hash(blockID: str, prev_hash: bytes, data: str) -> bytes:
    return sha3_256(blockID.encode() + prev_hash + data.encode()).digest()

def add_block(i):
    global block75Data
    prev_hash = blockChain[-1][1]
    blockID = format(i,'0160')
    data = randData()
    if i==75:
        block75Data = data
    current_hash = bytes.fromhex(make_hash(blockID, prev_hash, data).hex()[24:]) # 25~64 총 40개만 가져옴
    blockChain.append((blockID, current_hash, data, prev_hash))
    
def show_blockChain():
    for i, (blockID, current_hash, data, prev_hash) in enumerate(blockChain):
        # print(f'[블록 {i}]\nblock ID     : {blockID}\nprev hash    : {prev_hash.hex()}\ncurrent hash : {current_hash.hex()}\n')
        print(f'[block #{i}]\n prev hash    : {prev_hash.hex()}\n current hash : {current_hash.hex()}\n')
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

global block75Data
block75Data = (0,'1024')

make_genesis_block()
for i in range(1,101):
    add_block(i)
    
show_blockChain()
print()


##=========================================
##=============## verify ##================
##=========================================
# block75Data += '.'  # (여기를 주석 해제)
blockID = format(75,'0160')
blockChain[75] = (blockID, bytes.fromhex(make_hash(blockID, blockChain[74][1], block75Data).hex()[24:]), block75Data, blockChain[74][1])
verify_blockChain()
##=========================================

# 1024*n bit = 1MB