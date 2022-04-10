'''
    Module which implements the arcfour stream cipher encryption/decryption
'''

import secrets

def bytearray_to_bitarray(array):
    '''
        Function
    '''
    bitarray = []
    for byte in array:
        # Convert byte into string
        byte_string = f"{byte:08b}"
        for bit in byte_string:
            bitarray.append(int(bit))
    return bitarray

def bitarray_to_int(bitarray):
    '''
        Function which transforms a bitarray to its integer equivalent
    '''
    return int(''.join([str(b) for b in bitarray]), 2)

def pseudorandomise(keystream, seed):
    '''
        Implementation of Arcfour's pseudorandom number generator
    '''
    i = 0
    j = 0
    key_bytes = []
    for i in range(seed):
        i = (i + 1) % 256
        j = (j + keystream[i]) % 256
        keystream[i], keystream[j] = keystream[j], keystream[i]
        key_bytes.append(keystream[(keystream[i] + keystream[j]) % 256])
    return key_bytes

def generate_keystream(key):
    '''
        Function which generates the keystream to encrypt the message
    '''
    keystream = []
    # key = bytearray.fromhex(key)
    keylength = len(key)
    for i in range(256):
        keystream.append(i)
    j = 0
    for i in range(256):
        j = (j + keystream[i] + key[i % keylength]) % 256
        keystream[i], keystream[j] = keystream[j], keystream[i]
    
    keystream = pseudorandomise(keystream, 256)

    # for byte in keystream:
    #     print(f"{byte:02x}", end="")
    # print()
    return keystream

def arcfour_encrypt(text, key=None, ransom=False, **kwargs):
    '''
        Function wrapper for arcfour_parse (for encryption)
    '''
    package = arcfour_parse(text, key=key, ransom=ransom)
    return package[0], package[1], None

def arcfour_decrypt(text, key=None, ransom=False, **kwargs):
    '''
        Function wrapper for arcfour_parse (for decryption)
    '''
    return arcfour_parse(text, key=key, ransom=ransom, decrypt=True)

def arcfour_parse(text, key=None, decrypt=False, ransom=False):
    '''
        Function which encrypts AND decrypts the given text using the arcfour
        PRNG.
    '''
    if not ransom:
        if not decrypt:
            text = bytearray(text, 'utf-8')
        else:
            text = bytearray.fromhex(text)

    if key is None:
        key = bytearray(secrets.token_bytes(16))          # 128 bits
    else:
        key = bytearray.fromhex(key)

    keystream = generate_keystream(key)
    output = ""
    for index, byte in enumerate(text):
        new_byte = bytearray([byte ^ keystream[index % 256]])
        new_byte = f"{bitarray_to_int(bytearray_to_bitarray(new_byte)):02x}"
        output += new_byte
    
    key = ''.join(f'{x:02x}' for x in key)
    if not decrypt:
        return output, key
    else:
        output_i = int(output, 16)
        if ransom:
            return output_i.to_bytes((len(output) * 4) // 8, byteorder='big')
        return output_i.to_bytes((len(output) * 4) // 8, byteorder='big').decode('utf-8')

if "__main__" == __name__:
    key, text  = arcfour_parse("The quick brown fox jumps over the lazy dog.", key="63727970746969")
    print(f"Your encrypted text is: {text}\nYour key is: {key}")
    key, text = arcfour_parse(text, key=key, decrypt=True)
    print(f"Your decrypted text is: {text}")
    assert text == "The quick brown fox jumps over the lazy dog."