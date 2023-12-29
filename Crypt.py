def LSFRKeyGen(iv, dataLen) -> list:
    state = 0 or iv
    feedback = 0x87654321
    key = []
        
    for i in range(0, dataLen):
        #print(f'Current key is {"".join(chr(byte) for byte in key)}')
        
        for j in range(0, 8):
                
            LSB = bin(state)[-1]
            if (LSB == '1'):
                state = (state >> 1) ^ feedback
            else:
                state = state >> 1
                
        keyByte = int(bin(state)[-8:], 2)
        key.append(keyByte)
            
    return key
            
def XORData(data: bytes, key: bytes, dataLen: int) -> list:
    xor = []
    
    for i in range(0, dataLen):

        xorByte = data[i] ^ key[i] 
        #print(f'In XORDATA: data[i] = {ord(data[i])}, key[i] = {key[i]}')
        xor.append(xorByte)
        
    return xor


def Crypt(data: bytes, initialValue: int) -> bytes:
    #data = data.decode('unicode-escape')
    #print(data)
    #print(f'IV is {iv}')
    dataLen = len(data)
    key = LSFRKeyGen(initialValue, dataLen)
    EncryptBytes = XORData(data, key, dataLen)
    print(EncryptBytes)
    
    outBytes = ''.join(['\\x{:02x}'.format(x) for x in EncryptBytes])
    outStr = ''.join(chr(byte) for byte in EncryptBytes)
    
    return f'---Data Output---\nAs String: {outStr}\nAs Bytes: {outBytes}'
    
    
    
if __name__ == '__main__':
                    
    test1 = b'apple'                
    test2 = b'\xcd\x01\xef\xd7\x30'
    test3 = b'Thisisteststring'            
        
    print(Crypt(test1, 0x12345678))
    print(Crypt(test2, 0x12345678))
    print(Crypt(test3, 0x12345678))
    print(Crypt(b'\xf8\x19\xf6\xc8\x3c\x40\x56\xbc\xb9\xb3\xec\x88\xc2\x15\x9f\x01', 0x12345678))
    #print(Crypt(input('Enter your data: ').encode('utf-8'), 0x12345678))