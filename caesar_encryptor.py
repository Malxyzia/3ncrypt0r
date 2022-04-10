
def find_new_character(letter, cipher, alphabet):
    alphabet_length = len(alphabet)
    new_index = (alphabet.index(letter) + cipher) % alphabet_length
    return alphabet[new_index]

def caesar_encrypt(payload, cipher, alphabet,
                    keep_case=False, whitespace=True, special_chars=False):
    '''
        Function which encrypts an ASCII payload by the cipher provided by way
        of the Caesar Cipher.

        Arguments:
            payload (str)   - Plaintext to be encrypted
            cipher  (int)   - Number to shuffle the letters by
        
        Keyword Arguments:
            keep_case       (bool)  - Indicates whether plaintext should preserve
                                        upper case letters
            whitespace      (bool)  - Indicates whether plaintext should have whitespace
            special_chars   (bool)  - Indicates whether non-alphabetical chars should
                                        be stripped
    '''
    # Handle plaintext requirements:
    if not keep_case:
        payload = payload.lower()
    if not whitespace:
        payload = payload.strip(" ")
    
    # Encrypt plaintext
    encrypt_msg = ""
    for letter in payload:

        # Ignore if letter not in given alphabet
        if letter not in alphabet:
            
            # Check if special char is a letter
            if letter.isalpha():
                if letter.lower() in alphabet and keep_case:
                    encrypt_msg += find_new_character(letter.lower(), cipher, alphabet).upper()
                    continue
                
                elif letter.upper() in alphabet and keep_case:
                    encrypt_msg += find_new_character(letter.upper(), cipher, alphabet).lower()
                    continue
                    
            encrypt_msg += letter if special_chars or (whitespace and letter == " ") else "" 
            continue
               
        encrypt_msg += find_new_character(letter, cipher, alphabet)
    
    return encrypt_msg

def caesar_decrypt(payload, cipher, alphabet,
                    keep_case=False, whitespace=True, special_chars=False):
    '''
        Function which decrypts an ASCII payload by the cipher provided by way
        of the Caesar Cipher.

        Arguments:
            payload (str)   - Plaintext to be encrypted
            cipher  (int)   - Number to shuffle the letters by
        
        Keyword Arguments:
            keep_case       (bool)  - Indicates whether plaintext should preserve
                                        upper case letters
            whitespace      (bool)  - Indicates whether plaintext should have whitespace
            special_chars   (bool)  - Indicates whether non-alphabetical chars should
                                        be stripped
    '''
    # Handle plaintext requirements:
    if not keep_case:
        payload = payload.lower()
    if not whitespace:
        payload = payload.strip(" ")
    
    # Encrypt plaintext
    decrypt_msg = ""
    for letter in payload:

        # Ignore if letter not in given alphabet
        if letter not in alphabet:
            
            # Check if special char is a letter
            if letter.isalpha():
                if letter.lower() in alphabet and keep_case:
                    decrypt_msg += find_new_character(letter.lower(), -cipher, alphabet).upper()
                    continue
                
                elif letter.upper() in alphabet and keep_case:
                    decrypt_msg += find_new_character(letter.upper(), -cipher, alphabet).lower()
                    continue
                    
            decrypt_msg += letter if special_chars or (whitespace and letter == " ") else "" 
            continue
               
        decrypt_msg += find_new_character(letter, -cipher, alphabet)
    
    return decrypt_msg

if __name__ == "__main__":
    e = caesar_encrypt("Hello my name is Andre mwhahahaha", 7, "abcdefghijklmnopqrstuvwxyz", keep_case=True)
    print(e)
    d = caesar_decrypt(e, 7, "abcdefghijklmnopqrstuvwxyz", keep_case=True)
    print(d)