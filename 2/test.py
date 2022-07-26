# 160비트 -> 20바이트 : 0x0000000000000000000000000000000000000000 

for i in range(11,20):
    '''
    blockID = format((i//16)*10 + i%16,'040').encode() # 20byte 160bit
    blockID = hex().ljust(40,'0')#.encode()
    print(blockID)
    '''
    print(hex(i)[2:].rjust(40,'0')) # TxID : 160bit