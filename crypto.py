######################################################################
# crypto.py
# 
# @usage
# 
#     1. Requirements
#     
#         pip install pycrypto
#     
#     2. Import this file
#     
#         from crypto import Crypto
#     
#     3. Let's Encryption / Decryption
#     
#         [e.g.]
#         key = 'this is a secret key'
#         plainText = 'this is a plain text'
#         crypto = Crypto()
#         # When Encryption for CBC mode
#         encrypted = crypto.EncryptCBC(key, plainText)
#     
######################################################################
import binascii
import math
import sys
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter

class Crypto:
    
    def __init__(self):
        self.vMajor = sys.version_info.major
        self.vMinor = sys.version_info.minor
        self.vMicro = sys.version_info.micro
    
    
    ##################################################
    # Encrypt using CBC mode.
    # @param key: [str] The secret key.
    # @param plainText: [str] The plain text.
    # @return [str] The encrypted text.
    ##################################################
    def EncryptCBC(self, key, plainText):
        mul = math.ceil(len(plainText) / 16)
        plainText = plainText.zfill(16 * mul)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key[:32], AES.MODE_CBC, iv)
        cipherText = cipher.encrypt(plainText)
        return binascii.hexlify(iv + cipherText).decode('utf-8')
    
    
    ##################################################
    # Decrypt using CBC mode.
    # @param key: [str] The secret key.
    # @param cipherText: [str] The encrypted text.
    # @return [str] The plain text.
    ##################################################
    def DecryptCBC(self, key, cipherText):
        rowCipherText = binascii.unhexlify(cipherText)
        iv = rowCipherText[:16]
        encrypted = rowCipherText[16:]
        cipher = AES.new(key[:32], AES.MODE_CBC, iv)
        return cipher.decrypt(encrypted).decode('utf-8').lstrip('0')
    
    
    ##################################################
    # Verify using CBC mode.
    # @param key: [str] The secret key.
    # @param plainText: [str] The plain text.
    # @param cipherText: [str] The encrypted text.
    # @return [str] The plain text.
    ##################################################
    def VerifyCBC(self, key, plainText, cipherText):
        decrypted = self.DecryptCBC(key, cipherText)
        return plainText == decrypted
    
    
    ##################################################
    # Encrypt using CTR mode.
    # @param key: [str] The secret key.
    # @param plainText: [str] The plain text.
    # @return [str] The encrypted text.
    ##################################################
    def EncryptCTR(self, key, plainText):
        iv = Random.new().read(AES.block_size)
        ctr = Counter.new(AES.block_size * 8, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = AES.new(key[:32], AES.MODE_CTR, counter=ctr)
        cipherText = cipher.encrypt(plainText)
        return binascii.hexlify(iv + cipherText).decode('utf-8')
    
    
    ##################################################
    # Decrypt using CTR mode.
    # @param key: [str] The secret key.
    # @param cipherText: [str] The encrypted text.
    # @return [str] The plain text.
    ##################################################
    def DecryptCTR(self, key, cipherText):
        rowCipherText = binascii.unhexlify(cipherText)
        iv = rowCipherText[:16]
        encrypted = rowCipherText[16:]
        ctr = Counter.new(AES.block_size * 8, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = AES.new(key[:32], AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(encrypted).decode('utf-8')


    ##################################################
    # Verify using CTR mode.
    # @param key: [str] The secret key.
    # @param plainText: [str] The plain text.
    # @param cipherText: [str] The encrypted text.
    # @return [str] The plain text.
    ##################################################
    def VerifyCTR(self, key, plainText, cipherText):        
        decrypted = self.DecryptCTR(key, cipherText)
        return plainText == decrypted

