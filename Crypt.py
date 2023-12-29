# Takes initial value supplied to Crypt, produces a key as a bytes object
def LSFRKeyGen(iv, dataLen) -> bytes:
    state = 0 or iv
    feedback = 0x87654321
    key = []
        
    # For each byte in data, cycle the Linear Shift Feedback Register 8 times, extract the lowest byte, append to key bytes    
    for i in range(0, dataLen):
        
        for j in range(0, 8):
            
            # Check the lowest significant bit, if it's 1, logical right shift the current register state by 1 
            # Then XOR with the preset feedback
            LSB = bin(state)[-1]
            if (LSB == '1'):
                state = (state >> 1) ^ feedback
            # Otherwise, if the lowest signficant bit is 0, logical right shift the current register state by 1
            else:
                state = state >> 1
        # Extract the lower 8 bits (1 byte) from the current register state, convert to int of base 2, append to current key        
        keyByte = int(bin(state)[-8:], 2)
        key.append(keyByte)
            
    return key

# Takes in data and key of equal length as bytes, performs a bitwise XOR operation between data and key
def XORData(data: bytes, key: bytes, dataLen: int) -> bytes:
    xor = []
    
    for i in range(0, dataLen):

        xorByte = data[i] ^ key[i] 
        xor.append(xorByte)
        
    return xor


# Takes in data as a bytes object & initial value as an integer, performs LSRF based encryption/decryption on data
def Crypt(data: bytes, initialValue: int) -> bytes:
    
    dataLen = len(data)
    key = LSFRKeyGen(initialValue, dataLen)
    EncryptBytes = XORData(data, key, dataLen)
    
    # Format byte output as a bytestring, string output as the character representation of each byte
    outBytes = ''.join(['\\x{:02x}'.format(x) for x in EncryptBytes])
    outStr = ''.join(chr(byte) for byte in EncryptBytes)
    
    return f'---Data Output---\nAs String: {outStr}\nAs Bytes: {outBytes}'
    
    
    
if __name__ == '__main__':
    
    # Test Cases
    test1 = b'apple'                
    test1b = b'\xcd\x01\xef\xd7\x30' # 'apple' in bytes
    test2 = b'Thisisateststring'
    test2b = b'\xf8\x19\xf6\xc8\x3c\x40\x43\xad\xaf\xb4\xeb\x8f\xc4\x0e\x98\x08\x86' # 'Thisisateststring' in bytes            
        
    print(Crypt(test1, 0x12345678))
    print(Crypt(test1b, 0x12345678))
    print(Crypt(test2, 0x12345678))
    print(Crypt(test2b, 0x12345678))
