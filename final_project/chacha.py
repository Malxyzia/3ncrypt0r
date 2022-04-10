'''
    Module which implements the ChaCha20 Stream Cipher
'''

from random import random
import secrets

CONSTANT = "expand 32-byte k"
PAD_BYTE = bytearray(1)[0]

def bytearray_to_bitarray(array):
    '''
        Function which converts a bytearray to a bitarray
    '''
    bitarray = []
    for byte in array:
        # Convert byte into string
        byte_string = f"{byte:08b}"
        for bit in byte_string:
            bitarray.append(int(bit))
    if len(array) == 0:
        bitarray.append('0' * 8)
    return bitarray

def bitarray_to_int(bitarray):
    '''
        Function which transforms a bitarray to its integer equivalent
    '''
    return int(''.join([str(b) for b in bitarray]), 2)

def int_to_bitarray(integer, bits):
    '''
        Function which transforms an integer into a bitarray with <bits> length
    '''
    return [int(i) for i in f"{integer:0{bits}b}"]

def rotate_array(array, n):
    '''
        Function which circularly rotates an array to the left <n> times
    
    '''
    for i in range(n):
        array = array[1:] + array[:1]
    return array

def do_xor(bitarray1, bitarray2):
    '''
        Function which takes two bit arrays and XORs them
    '''
    result = []
    for i, bit in enumerate(bitarray1):
        result.append(bit ^ bitarray2[i])
    return result

def bitarray_additon(num1, num2):
    '''
        Function which facilitates the addition of two bitarrays
    '''
    num1 = bitarray_to_int(num1)
    num2 = bitarray_to_int(num2)
    result = (num1 + num2) % 2**32
    return int_to_bitarray(result, 32)

def init_matrix(key, IV, counter):
    '''
        Function which generates the initial matrix state for ChaCha20
    '''
    matrix = []
    constant = bytearray_to_bitarray(bytearray(CONSTANT, 'utf-8'))
    for i in range(4):
        matrix.append(constant[i * 32 : (i + 1) * 32])
    for i in range(4):
        matrix.append(key[i * 32 : (i + 1) * 32])
    if len(key) == 128:
        for i in range(4):
            matrix.append(key[i * 32 : (i + 1) * 32])
    else:
        for i in range(4, 8):
            matrix.append(key[i * 32 : (i + 1) * 32])
    
    matrix.append(counter)
    for i in range(0, 3):
        matrix.append(IV[i * 32 : (i + 1) * 32])
    return matrix

def shuffle_matrix(matrix, cells):
    # Mix 1
    matrix[cells[0]] = bitarray_additon(matrix[cells[0]], matrix[cells[3]])
    matrix[cells[3]] = do_xor(matrix[cells[3]], matrix[cells[0]])
    matrix[cells[3]] = rotate_array(matrix[cells[3]], 16)
    
    # Mix 2
    matrix[cells[2]] = bitarray_additon(matrix[cells[2]], matrix[cells[3]])
    matrix[cells[1]] = do_xor(matrix[cells[1]], matrix[cells[2]])
    matrix[cells[1]] = rotate_array(matrix[cells[1]], 12)

    # Mix 3
    matrix[cells[0]] = bitarray_additon(matrix[cells[0]], matrix[cells[1]])
    matrix[cells[3]] = do_xor(matrix[cells[3]], matrix[cells[0]])
    matrix[cells[3]] = rotate_array(matrix[cells[3]], 8)

    # Mix 4
    matrix[cells[2]] = bitarray_additon(matrix[cells[2]], matrix[cells[3]])
    matrix[cells[1]] = do_xor(matrix[cells[1]], matrix[cells[2]])
    matrix[cells[1]] = rotate_array(matrix[cells[1]], 7)

    return matrix

def randomise_matrix(matrix):
    '''
        Function which uses ChaCha20's pseudorandomiser to generate a random
        matrix state
    '''
    for i in range(10):
        if i % 2 == 0:
            matrix = shuffle_matrix(matrix, [0, 5, 10, 15])
            matrix = shuffle_matrix(matrix, [1, 6, 11, 12])
            matrix = shuffle_matrix(matrix, [2, 7, 8, 13])
            matrix = shuffle_matrix(matrix, [3, 4, 9, 14])
        else:
            matrix = shuffle_matrix(matrix, [0, 4, 8, 12])
            matrix = shuffle_matrix(matrix, [1, 5, 9, 13])
            matrix = shuffle_matrix(matrix, [2, 6, 10, 14])
            matrix = shuffle_matrix(matrix, [3, 7, 11, 15])

    return matrix

def generate_keystream(key, IV, counter):
    matrix = init_matrix(key, IV, counter)
    matrix = randomise_matrix(matrix)
    return matrix

def chacha_encrypt(text, key=None, IV=None, ransom=False, **kwargs):
    '''
        Wrapper function for chacha_parse specifically for ransomware mode
    '''
    return chacha_parse(text, key=key, IV=IV, ransom=ransom)

def chacha_decrypt(text, key=None, IV=None, ransom=False, **kwargs):
    '''
        Wrapper function for chacha_parse specifically for ransomware mode
    '''
    return chacha_parse(text, key=key, IV=IV, decrypt=True, ransom=ransom)

def chacha_parse(text, key=None, IV=None, decrypt=False, ransom=False):
    '''
        Function which encrypts/decrypts the given text using the ChaCha stream
        cipher
    '''
    if not ransom:
        if not decrypt:
            text = bytearray(text, 'utf-8')
        else:
            text = bytearray.fromhex(text)

    if key is None:
        key = bytearray(secrets.token_bytes(32))          # 256 bits
    else:
        key = bytearray.fromhex(key)

    if IV is None:
        IV = bytearray(secrets.token_bytes(12))           # 96 bit nonce
    else:
        IV = bytearray.fromhex(IV)
    
    key = bytearray_to_bitarray(key)
    IV = bytearray_to_bitarray(IV)

    if not decrypt:
        # Handle padding
        to_pad = 32
        text_length = len(text) * 8
        if text_length % 32 != 0:
            to_pad = (text_length // 32 + 1) * 32 - text_length
        for i in range((to_pad // 8) - 1):
            text.append(PAD_BYTE)
        text.append(to_pad // 8)
    text = bytearray_to_bitarray(text)
    
    keystream = generate_keystream(key, IV, bytearray_to_bitarray(bytearray.fromhex('0' * 8)))

    output = ""
    for i in range(len(text) // 32):
        text_word = bitarray_to_int(text[i * 32 : (i + 1) * 32])
        key_word = bitarray_to_int(keystream[i % 16])
        new_word = (text_word ^ key_word)
        new_word = new_word.to_bytes((new_word.bit_length() + 7) // 8, 'big')    
        new_word = f"{bitarray_to_int(bytearray_to_bitarray(new_word)):02x}"
        if len(new_word) != 8:
            new_word = '0' * (8 - len(new_word)) + new_word
        output += new_word
    
    key = bitarray_to_int(key)
    key = key.to_bytes((key.bit_length() + 7) // 8, 'big')
    key = f"{bitarray_to_int(bytearray_to_bitarray(key)):02x}"
    if len(key) != 64:
        key = '0' * (64 - len(key)) + key

    IV = bitarray_to_int(IV)
    IV = IV.to_bytes((IV.bit_length() + 7) // 8, 'big')
    IV = f"{bitarray_to_int(bytearray_to_bitarray(IV)):02x}"
    if len(IV) != 24:
        IV = '0' * (24 - len(IV)) + IV

    if not decrypt:
        return output, key, IV
    else:
        # Strip padding
        to_remove = int(output[-2:], 16) * 2
        output = output[:-to_remove]
        output_i = int(output, 16)
        if ransom:
            return output_i.to_bytes((len(output) * 4) // 8, byteorder='big')
        return output_i.to_bytes((len(output) * 4) // 8, byteorder='big').decode('utf-8').rstrip('\x00')

if "__main__" == __name__:
    text, key, iv  = chacha_parse("The quick brown fox jumps over the lazy dog.")
    print(f"Your encrypted text is: {text}\nYour key is: {key}\nYour IV is: {iv}")
    text = chacha_parse(text, key=key, IV=iv, decrypt=True)
    print(f"Your decrypted text is: {text}")
    assert text == "The quick brown fox jumps over the lazy dog."

    # Stress test nonce and key generation:
    print(f"Testing Key/IV Reliability: [{100 * ' '}] 0%", end='')
    for i in range(10000):
        print(f"\rTesting Key/IV Reliability: [{(i + 1) // 100 * '>' + (100 - ((i + 1) // 100)) * ' '}] {(i + 1)/100:.2f}%", end='')
        cipher, key, iv = chacha_parse("我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~")
        plaintext = chacha_parse(cipher, key=key, IV=iv, decrypt=True)
        assert plaintext == "我是构建这个狡猾的实现的了不起的家伙。不要像农民一样侮辱我！ :3~~~"
    print()
