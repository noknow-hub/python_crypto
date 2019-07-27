from crypto import Crypto

print('//////////////////////////////////////////////////')
print('// Demo for Crypto')
print('//////////////////////////////////////////////////')
print('')

key = 'id8e20fmsyy14oxld9enau1088sjxrpa'
plainText = 'hello world'

print('key: ' + key)
print('plainText: ' + plainText)
print('')

crypto = Crypto()

print('// Python Version')
print('version major: ' + str(crypto.vMajor))
print('version minor: ' + str(crypto.vMinor))
print('version micro: ' + str(crypto.vMicro))
print('')

print('// CBC Mode')
encrypted = crypto.EncryptCBC(key, plainText)
print('encrypted: ' + encrypted)
decrypted = crypto.DecryptCBC(key, encrypted)
print('decrypted: ' + decrypted)
verfied = crypto.VerifyCBC(key, plainText, encrypted)
print('verfied: ' + str(verfied))
print('')

print('// CTR Mode')
encrypted = crypto.EncryptCTR(key, plainText)
print('encrypted: ' + encrypted)
decrypted = crypto.DecryptCTR(key, encrypted)
print('decrypted: ' + decrypted)
verfied = crypto.VerifyCTR(key, plainText, encrypted)
print('verfied: ' + str(verfied))
print('')

