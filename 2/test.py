# print(len("1143ca9042497929851e4507f4edf4a80be8bd741143e5f0644c8415c0e7e459"))

hex1 = "2b7f2009cd08ac17c81b87917bcfe5f296a755ff8f6e5bc36dae21ad0ab34ed8" # 256 -> 96+160 24개||40개
# hex1 = "2b7f2009cd08ac17c81b87918bcfe5f296a755ff8f6e5bc36dae21ad0ab34ed8" # 256 -> 96+160
byte1 = b'+\x7f \t\xcd\x08\xac\x17\xc8\x1b\x87\x91{\xcf\xe5\xf2\x96\xa7U\xff\x8fn[\xc3m\xae!\xad\n\xb3N\xd9'

print(byte1)
print(byte1.hex())
print(byte1.hex()[:5])
print(byte1.hex()[:5].encode())
print(bytes(byte1.hex()[:5].encode()))
print(bytes.fromhex(byte1.hex()[:40]))


# print(bin( int(hex1,16) ))
# print(bin( int(hex1,16)&( (1<<160)-1 ) ))
# print(bin( int(byte1.hex(),16)&((1<<160)-1) ))
# print(hex( int(hex1,16)&((1<<160)-1) )) 
# if (len(bin( int(hex1,16)&( (1<<160)-1 ) )))==161:
    # print(bin( int(hex1,16)&( (1<<160)-1 )^(1<<159) ))
# else:
    # bin( int(hex1,16)&( (1<<160)-1 ) )
    
    
# print(bin((1<<160)-1))
# print(len(bin( (1<<160)-1 )))
# print(bin( ((1<<4)-1)))
# print(bin( ((1<<4)-1) ^(1<<3)))
# print(len("2b7f2009cd08ac17c81b87917bcfe5f296a755ff8f6e5bc36dae21ad0ab34ed8"[24:]))
# print(b'0'*160)

# print("30616563343432396564663831623537626164356262653261303964373536363235633530323862".encode().hex())

print(len("5c59acdf312726d39c136c0e87b2a42ad47b3301"))