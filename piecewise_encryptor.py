'''
x^2+7x-18
900x-1800
length of num, which function,
'''
import secrets
import math

ENCRYPTION = {
    0 : lambda x: x**2 + 7*x - 18,
    1 : lambda x: 900*x-1800
}

DECRYPTION = {
    0 : lambda x: (-7 + math.sqrt(49 - 4 * (-18 - x))) / 2,
    1 : lambda x: (x + 1800) / 900
}

def encrypt_char(e_function, char, offset):
    '''
        Encrypts a character and outputs the corresponding encryption packet

        Packet: <e_function used><digits of result>-<result> where:
            <e_function used>   - 0 or 1 (mapped by ENCRYPTION)
            <digits of result>  - number of digits of the actual encrypted char
            <result>            - encrypted char
    '''

    packet = str(e_function)
    encrypted_char = ENCRYPTION[e_function](ord(char)) + offset
    packet += (str(len(str(encrypted_char))) + '-')
    packet += str(encrypted_char)
    e_function = secrets.randbelow(2)
    return packet, e_function

def decrypt_char(d_function, char, offset):
    '''
        Decrypts a character
    '''
    decrypted_char = DECRYPTION[d_function](int(char) - offset)
    return chr(int(decrypted_char))

def piecewise_encrypt(plaintext, offset):
    ciphertext = ""

    # Generate a starting encrypt function
    e_function = secrets.randbelow(2)    

    # Go through every char in the plaintext
    for char in plaintext:
        packet, e_function = encrypt_char(e_function, char, offset)
        ciphertext += packet

    return ciphertext

def read_digits(ciphertext, index):
    # Include '-' as part of buffer
    buffer = 1
    digits = ""
    for char in ciphertext[index:]:
        if char == '-':
            break
        buffer += 1
        digits += char
    return int(digits), buffer

def piecewise_decrypt(ciphertext, offset):
    plaintext = ""
    d_function = 0
    digits = 0
    buffer = 0
    character = ''
    # Read cipher text
    for index, char in enumerate(ciphertext):
        
        # Check if we need to read new packet
        if digits == 0:
            d_function = int(char)
            digits, buffer = read_digits(ciphertext, index + 1)
        elif buffer != 0:
            buffer -= 1
        else:
            character += char
            digits -= 1
            if digits == 0:
                plaintext += decrypt_char(d_function, character, offset)

                # Reset
                digits = 0
                buffer = 0
                character = ''
    
    return plaintext

if __name__ == "__main__":
    e = piecewise_encrypt("This is an ECB coded message | 这是一条 ECB 编码的消息 | هذه رسالة مشفرة في ECB", 777)
    print(e)
    d = piecewise_decrypt(e, 777)
    assert d == "This is an ECB coded message | 这是一条 ECB 编码的消息 | هذه رسالة مشفرة في ECB"

