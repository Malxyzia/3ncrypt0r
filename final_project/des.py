'''
    Module which handles DES encryption

    Verification sites:
    https://the-x.cn/en-US/cryptography/Des.aspx
    https://www.geeksforgeeks.org/data-encryption-standard-des-set-1
    https://www.javacardos.com/tools/des-encrypt-decrypt
    https://emvlab.org/descalc/
    https://gchq.github.io/CyberChef/#recipe=DES_Encrypt
    (Note for Cyberchef, it adds extra padding at the end)
'''
import secrets

PAD_BYTE = bytearray(1)[0]
KEY_BIT_ORDER1 = [  57, 49, 41, 33, 25, 17,  9,
                     1, 58, 50, 42, 34, 26, 18,
                    10,  2, 59, 51, 43, 35, 27,
                    19, 11,  3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                     7, 62, 54, 46, 38, 30, 22,
                    14,  6, 61, 53, 45, 37, 29,
                    21, 13,  5, 28, 20, 12,  4  ]
KEY_BIT_ORDER2 = [  14, 17, 11, 24,  1,  5,  3,
                    28, 15,  6, 21, 10, 23,  19,
                    12,  4, 26,  8, 16,  7,  27,
                    20, 13,  2, 41, 52, 31,  37,
                    47, 55, 30, 40, 51, 45,  33,
                    48, 44, 49, 39, 56, 34,  53,
                    46, 42, 50, 36, 29, 32  ]
KEY_ROTATION = [    1,  1,  2,  2,  2,  2,  2,  2,
                    1,  2,  2,  2,  2,  2,  2,  1   ]
INITIAL_P = [   58,    50,   42,    34,    26,   18,    10,    2,
                60,    52,   44,    36,    28,   20,    12,    4,
                62,    54,   46,    38,    30,   22,    14,    6,
                64,    56,   48,    40,    32,   24,    16,    8,
                57,    49,   41,    33,    25,   17,     9,    1,
                59,    51,   43,    35,    27,   19,    11,    3,
                61,    53,   45,    37,    29,   21,    13,    5,
                63,    55,   47,    39,    31,   23,    15,    7    ]
EXPANSION_BITS = [  32,     1,    2,     3,     4,    5,
                     4,     5,    6,     7,     8,    9,
                     8,     9,   10,    11,    12,   13,
                    12,    13,   14,    15,    16,   17,
                    16,    17,   18,    19,    20,   21,
                    20,    21,   22,    23,    24,   25,
                    24,    25,   26,    27,    28,   29,
                    28,    29,   30,    31,    32,    1 ]
INITIAL_P_INV = [   40,     8,   48,    16,    56,   24,    64,   32,
                    39,     7,   47,    15,    55,   23,    63,   31,
                    38,     6,   46,    14,    54,   22,    62,   30,
                    37,     5,   45,    13,    53,   21,    61,   29,
                    36,     4,   44,    12,    52,   20,    60,   28,
                    35,     3,   43,    11,    51,   19,    59,   27,
                    34,     2,   42,    10,    50,   18,    58,   26,
                    33,     1,   41,     9,    49,   17,    57,   25    ]


S_BOXES = [
    [
        [ 14,   4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7 ],
        [ 0,  15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8 ],
        [ 4,   1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0 ],
        [ 15,  12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13 ]
    ],
    [
        [   15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10 ],
        [    3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5 ],
        [    0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15 ],
        [   13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9 ]
    ],
    [
        [   10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8 ],
        [   13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1 ],
        [   13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7 ],
        [    1, 10,  13,  0,   6 , 9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12 ]
    ],
    [
        [    7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15 ],
        [   13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9 ],
        [   10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4 ],
        [    3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14 ]
    ],
    [
        [    2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,   9 ],
        [   14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,   6 ],
        [    4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0,  14 ],
        [   11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,   3 ]
    ],
    [
        [   12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11 ],
        [   10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8 ],
        [    9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6 ],
        [    4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13 ]
    ],
    [
        [    4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1 ],
        [   13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6 ],
        [    1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2 ],
        [    6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12 ]
    ],
    [
        [   13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7 ],
        [    1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2 ],
        [    7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8 ],
        [    2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11 ],       
    ]
]

PERMUTATION = [ 16,   7,  20,  21,
                29,  12,  28,  17,
                 1,  15,  23,  26,
                 5,  18,  31,  10,
                 2,   8,  24,  14,
                32,  27,   3,   9,
                19,  13,  30,   6,
                22,  11,   4,  25   ]
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

def do_xor(bitarray1, bitarray2):
    '''
        Function which takes two bit arrays and XORs them
    '''
    result = []
    for i, bit in enumerate(bitarray1):
        result.append(bit ^ bitarray2[i])
    return result

def int_to_bitarray(num):
    '''
        Function which converts an integer into a 64-bit string
    '''
    bit_string = list(f"{num:08b}")
    bit_string = [int(b) for b in bit_string]
    padding = 64 - len(bit_string)
    bitarray = [0 for i in range(padding)] + bit_string
    return bitarray

def do_ECB(block, key, IV, *args, decrypt=False):
    '''
        Function which handles ECB encryption/decryption
    '''
    outputblock = do_des(block, key, decrypt=decrypt)
    IV = outputblock
    return outputblock, IV

def do_CBC(block, key, IV, *args, decrypt=False):
    '''
        Function which handles CBC encryption/decryption
    '''
    # CBC handling for encryption
    if not decrypt:
        block = do_xor(block, IV)
    
    # Actual encryption
    outputblock = do_des(block, key, decrypt=decrypt)

    # CBC handling for decryption
    if decrypt:
        outputblock = do_xor(IV, outputblock)
    IV = block if decrypt else outputblock
    return outputblock, IV

def do_PCBC(block, key, IV, counter, decrypt=False):
    '''
        Function which handles PCBC encryption/decryption
    '''
    original = block
    # PCBC handling for encryption
    if not decrypt:
        block = do_xor(block, IV)
    
    # Actual encryption
    outputblock = do_des(block, key, decrypt=decrypt)

    # PCBC handling for decryption
    if decrypt:
        outputblock = do_xor(IV, outputblock)
    IV = do_xor(original, outputblock)
    return outputblock, IV

def do_CTR(block, key, IV, counter, decrypt=False):
    '''
        Function which handles CTR encryption/decryption
    '''
    nonce = do_xor(IV, int_to_bitarray(counter))
    outputblock = do_des(nonce, key)
    outputblock = do_xor(outputblock, block)
    return outputblock, IV

def do_CFB(block, key, IV, *args, decrypt=False):
    '''
        Function which handles CFB encryption/decryption
    '''
    outputblock = do_des(IV, key)
    outputblock = do_xor(outputblock, block)

    if decrypt:
        IV = block
    else:
        IV = outputblock
    return outputblock, IV

def do_OFB(block, key, IV, *args, decrypt=False):
    '''
        Function which handles OFB encryption/decryption
    '''
    outputblock = do_des(IV, key)
    IV = outputblock
    outputblock = do_xor(outputblock, block)
    return outputblock, IV


MODES = {
    "ECB" : do_ECB,
    "CBC" : do_CBC,
    "PCBC" : do_PCBC,
    "CTR" : do_CTR,
    "CFB" : do_CFB,
    "OFB" : do_OFB
}


def encrypt_des(plaintext, key=None, mode="ECB", IV=None, ransom=False):
    '''
        Function which encrypts a plaintext using the DES algorithm.

        Inputs:
            plaintext   (str)    - String which is to be encrypted. Is converted
                                    to unicode
            key         (str)    - 64-bit hexadecimal string used to encrypt the
                                    plaintext. If none is given, one is generated
            mode        (str)    - One of three modes (ECB, CBC, CTR). Default is
                                    ECB
            IV          (str)    - 64-bit hexadecimal string that must be given if
                                    mode is CBC or CTR.
        Returns:
            cipher_hex  (str)    - The ciphertext in a hexadecimal string
            key         (str)    - The key used as a hexadecimal string
            IV          (str)    - The initialisation vector used, as a hexadecimal
                                    string. Is None if no IV given
    '''
    # Parse plaintext as unicode bits
    if not ransom:
        plaintext_bytes = bytearray(plaintext, "utf-8")
    else:
        plaintext_bytes = plaintext
    initial_IV = IV

    # Handle padding
    padding_num = 64
    if (len(plaintext_bytes) * 8) % 64 != 0:
        remaining = ((len(plaintext_bytes) * 8) // 64 + 1) * 64 - (len(plaintext_bytes) * 8)
        padding_num = remaining // 8
    for i in range(padding_num - 1):
        plaintext_bytes.append(PAD_BYTE)
    plaintext_bytes.append(padding_num)

    # Generate key if needed
    if not key:
        key = bytearray(secrets.token_bytes(8))     # 64-bits
        # Reroll key to ensure first byte will never be 0
        while key[0] == 0:
            key = bytearray(secrets.token_bytes(8))
    else:
        # Convert hexadecimal key to binary bytes
        key = bytearray.fromhex(key)              
    key = bytearray_to_bitarray(key)

    # Check if initialisation vector needs to be generated
    if mode != "ECB":
        if not IV:
            IV = bytearray(secrets.token_bytes(8))     # 64-bits
            # Reroll IV to ensure first byte will never be 0
            while IV[0] == 0:
                IV = bytearray(secrets.token_bytes(8))
        else:
            IV = bytearray.fromhex(IV)
        IV = bytearray_to_bitarray(IV)
        initial_IV = IV
    plaintext_bytes = bytearray_to_bitarray(plaintext_bytes)
    
    # Encrypt plaintext in 64-bit blocks
    ciphertext = ""
    for i in range(len(plaintext_bytes) // 64):
        plaintext_block = plaintext_bytes[i * 64 : (i + 1) * 64]

        cipherblock, IV = MODES[mode](plaintext_block, key, IV, i)
        ciphertext += ''.join([str(b) for b in cipherblock])

    # String together Ciphertext
    binary_string = ''.join([str(b) for b in ciphertext])
    cipher_hex = f"{int(binary_string, 2):02x}"
    if len(cipher_hex) % 8 != 0:
        padding = 8 - (len(cipher_hex) % 8)
        cipher_hex = '0' * padding + cipher_hex
    
    # String together key
    key_string = ''.join([str(b) for b in key])
    key = f"{int(key_string, 2):02x}"
    if len(key) % 8 != 0:
        key = '0' * (8 - (len(key) % 8)) + key

    # Handle IV output
    if mode != "ECB":
        IV_string = ''.join([str(b) for b in initial_IV])
        initial_IV = f"{int(IV_string, 2):02x}"
        if len(initial_IV) % 8 != 0:
            initial_IV = '0' + initial_IV
    return cipher_hex, key, initial_IV

def decrypt_des(ciphertext, key, mode="ECB", IV=None, ransom=False):
    '''
        Function which decrypts a ciphertext using the DES algorithm.

        Inputs:
            plaintext   (str)    - String which is to be encrypted. Is converted
                                    to unicode
            key         (str)    - 64-bit hexadecimal string used to encrypt the
                                    plaintext.
            mode        (str)    - One of three modes (ECB, CBC, CTR). Default is
                                    ECB
            IV          (str)    - 64-bit hexadecimal string that must be given if
                                    mode is CBC or CTR.
        Returns:
            plaintext   (str)    - The plaintext in unicode
    '''
    plaintext = ""

    # Unpack input data
    if not ransom:
        cipher_bytes = bytearray.fromhex(ciphertext)
    else:
        cipher_bytes = ciphertext
    cipher_bits = bytearray_to_bitarray(cipher_bytes)
    key = bytearray.fromhex(key)
    key = bytearray_to_bitarray(key)
    if mode != "ECB":
        IV = bytearray.fromhex(IV)
        IV = bytearray_to_bitarray(IV)

    for i in range(len(cipher_bits) // 64):
        cipher_block = cipher_bits[i * 64 : (i + 1) * 64]
        plainblock, IV = MODES[mode](cipher_block, key, IV, i, decrypt=True)
        plaintext += ''.join([str(b) for b in plainblock])

    # Strip padding
    to_remove = int(plaintext[-8:], 2) * 8
    plaintext = plaintext[:-to_remove]
    binary_string = ''.join([str(b) for b in plaintext])
    plaintext_i = int(binary_string, 2)
    
    if not ransom:
        return plaintext_i.to_bytes(len(plaintext) // 8, byteorder='big').decode('utf-8').rstrip('\x00')
    else:
        return plaintext_i.to_bytes(len(plaintext) // 8, byteorder='big')

def rotate_key(key, shift):
    '''
        Rotates the given key by <shift> number of bytes
        Returns the rotated key
    '''
    for i in range(shift):
        key = key[1:] + key[:1]
    return key

def create_subkeys(key):
    '''
        Creates 16 subkeys of 48-bit length from a given key.

        Returns them as an array.
    '''

    # Permute to 56-bit key
    permuted_key = key[:56]
    for index, order_bit in enumerate(KEY_BIT_ORDER1):
        permuted_key[index] = key[order_bit - 1]

    # Split key and create subkey halves
    left_keys = [permuted_key[:28]]
    right_keys = [permuted_key[28:]]

    for i in range(16):
        left_keys.append(rotate_key(left_keys[i], KEY_ROTATION[i]))
        right_keys.append(rotate_key(right_keys[i], KEY_ROTATION[i]))

    subkeys = [left_keys[i] + right_keys[i] for i in range(1, 17)]
    permuted_subkeys = [k[:48] for k in subkeys]
    for index, order_bits in enumerate(KEY_BIT_ORDER2):
        for i in range(16):
            permuted_subkeys[i][index] = subkeys[i][order_bits - 1]
    return permuted_subkeys

def expand_block(block):
    '''
        Hi
    '''
    e_block = [0 for i in range(48)]
    for index, order_bit in enumerate(EXPANSION_BITS):
        e_block[index] = block[order_bit - 1]
    return e_block

def feistel(subkey, right):
    '''
        Function
    '''

    # Expand right from 32-bits to 48-bits
    right = expand_block(right)

    # XOR subkey and right
    result = do_xor(subkey, right)
    bit_parts = []
    for i in range(8):
        bit_parts.append(result[i * 6 : (i + 1) * 6])

    # S-Box the each part
    bit_s_parts = [0 for k in range(8)]
    for index, part in enumerate(bit_parts):
        row = int(str(part[0]) + str(part[-1]), 2)
        col = int(''.join([str(k) for k in part[1:5]]), 2)
        bit_s_parts[index] = f"{S_BOXES[index][row][col]:04b}"

    bit_s_parts = [int(i) for i in ''.join(bit_s_parts)]

    # Permutate the S-box output
    output = [0 for k in range(32)]
    for index, order_bit in enumerate(PERMUTATION):
        output[index] = bit_s_parts[order_bit - 1]

    return output

def do_des(plaintext, key, decrypt=False):
    '''
        Function
    '''
    # Grab subkeys
    subkeys = create_subkeys(key)

    # Check if we are decrypting
    if decrypt:
        # We reverse order of keys when decrypting
        subkeys.reverse()

    # Permutate plaintext
    p_plaintext = [0 for i in range(64)]
    for index, order_bit in enumerate(INITIAL_P):
        p_plaintext[index] = plaintext[order_bit - 1]

    # Split into left and right
    left = [p_plaintext[:32]]
    right = [p_plaintext[32:]]

    # Iterate through each key with Feistel Function
    for index, subkey in enumerate(subkeys):
        left.append(right[index])
        feistel_output = feistel(subkey, right[index])
        left_prev = left[index]
        right_curr = do_xor(left_prev, feistel_output)
        right.append(right_curr)

    # Reverse final blocks
    interim_text = right[-1] + left[-1]

    # Inverse permutation
    ciphertext = [0 for k in range(64)]
    for index, order_bit in enumerate(INITIAL_P_INV):
        ciphertext[index] = interim_text[order_bit - 1]

    return ciphertext

if __name__ == "__main__":

    # Testing ECB
    cipher, key, iv = encrypt_des("This is an ECB coded message | 这是一条 ECB 编码的消息 | هذه رسالة مشفرة في ECB", mode="ECB")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = decrypt_des(cipher, key, mode="ECB", IV=iv).rstrip()
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This is an ECB coded message | 这是一条 ECB 编码的消息 | هذه رسالة مشفرة في ECB"

    # Testing CBC
    cipher, key, iv = encrypt_des("This message is coded with CBC | هذه الرسالة مشفرة بواسطة CBC | 此消息使用 CBC 編碼", mode="CBC")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = decrypt_des(cipher, key, mode="CBC", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with CBC | هذه الرسالة مشفرة بواسطة CBC | 此消息使用 CBC 編碼"

    # cipher, key, iv = encrypt_des("Hi, my name's Hayton! If you're readings this... why did you bother cracking this message?", mode="CBC")
    # print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    # plaintext = decrypt_des(cipher, key, mode="CBC", IV=iv).rstrip()
    # # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    # print(f"Your decrypted text translates to:\n{plaintext}")
    # assert plaintext == "This message is coded with CBC | هذه الرسالة مشفرة بواسطة CBC | 此消息使用 CBC 編碼"

    # Testing CTR
    cipher, key, iv = encrypt_des("此消息由 CTR 加密 | This message is encrypted by CTR | تم تشفير هذه الرسالة بواسطة نسبة النقر إلى الظهور (CTR)", mode="CTR")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = decrypt_des(cipher, key, mode="CTR", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "此消息由 CTR 加密 | This message is encrypted by CTR | تم تشفير هذه الرسالة بواسطة نسبة النقر إلى الظهور (CTR)"

    # Testing PCBC
    cipher, key, iv = encrypt_des("This message is coded with PCBC | هذه الرسالة مشفرة بواسطة PCBC | 此消息使用 PCBC 編碼", mode="PCBC")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = decrypt_des(cipher, key, mode="PCBC", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with PCBC | هذه الرسالة مشفرة بواسطة PCBC | 此消息使用 PCBC 編碼"

    # Testing CFB
    cipher, key, iv = encrypt_des("This message is coded with CFB | هذه الرسالة مشفرة بواسطة CFB | 此消息使用 CFB 編碼", mode="CFB")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = decrypt_des(cipher, key, mode="CFB", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with CFB | هذه الرسالة مشفرة بواسطة CFB | 此消息使用 CFB 編碼"

    # Testing OFB
    cipher, key, iv = encrypt_des("This message is coded with OFB | هذه الرسالة مشفرة بواسطة OFB | 此消息使用 OFB 編碼", mode="OFB")
    print(f"Your encrypted text is: {cipher}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
    plaintext = decrypt_des(cipher, key, mode="OFB", IV=iv).rstrip()
    # print(f"{int(''.join([str(b) for b in bytearray_to_bitarray(bytearray(plaintext, 'utf-8'))]), 2):02x}")
    print(f"Your decrypted text translates to:\n{plaintext}")
    assert plaintext == "This message is coded with OFB | هذه الرسالة مشفرة بواسطة OFB | 此消息使用 OFB 編碼"

    # Stress test reliability ECB:
    print(f"Testing ECB Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting ECB Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = encrypt_des("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="ECB")
        plaintext = decrypt_des(cipher, key, mode="ECB", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()
    # Stress test reliability CBC:
    print(f"Testing CBC Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting CBC Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = encrypt_des("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="CBC")
        plaintext = decrypt_des(cipher, key, mode="CBC", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()
    # Stress test reliability CTR:
    print(f"Testing CTR Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting CTR Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = encrypt_des("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="CTR")
        plaintext = decrypt_des(cipher, key, mode="CTR", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()
    
    # Stress test reliability PCBC:
    print(f"Testing PCBC Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting PCBC Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = encrypt_des("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="PCBC")
        plaintext = decrypt_des(cipher, key, mode="PCBC", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    # Stress test reliability CFB:
    print(f"Testing PCBC Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting CFB Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = encrypt_des("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="CFB")
        plaintext = decrypt_des(cipher, key, mode="CFB", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    # Stress test reliability OFB:
    print(f"Testing OFB Reliability: [{100 * ' '}] 0%", end='')
    for i in range(1000):
        print(f"\rTesting OFB Reliability: [{(i + 1) // 10 * '>' + (100 - ((i + 1) // 10)) * ' '}] {(i + 1)/10:.2f}%", end='')
        cipher, key, iv = encrypt_des("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~", mode="OFB")
        plaintext = decrypt_des(cipher, key, mode="OFB", IV=iv).rstrip()
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()

    print("\nTesting complete! Everything's functional!")