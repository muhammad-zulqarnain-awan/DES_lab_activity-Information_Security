import base64
import hashlib
from Crypto.Cipher import DES

password = "Password"
salt = b'\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'

def encrypt(plain_text):
    key = password.encode() + salt
    m = hashlib.md5(key)
    key = m.digest()
    (dk, iv) = (key[:8], key[8:])
    crypter = DES.new(dk, DES.MODE_CBC, iv)
    plain_text_bytes = plain_text.encode()
    plain_text_bytes += b'\x00' * (8 - len(plain_text_bytes) % 8)
    ciphertext = crypter.encrypt(plain_text_bytes)
    encode_string = base64.b64encode(ciphertext)
    return encode_string

def decrypt(encoded_string):
    ciphertext = base64.b64decode(encoded_string)
    key = password.encode() + salt
    m = hashlib.md5(key)
    key = m.digest()
    (dk, iv) = (key[:8], key[8:])
    crypter = DES.new(dk, DES.MODE_CBC, iv)
    plain_text = crypter.decrypt(ciphertext)
    plain_text = plain_text.rstrip(b'\x00')
    return plain_text.decode()

# Encryption
plain_text = "All Pakistani banks are under threat, and the Attack hours is 01:00 AM- 02:00 AM, on date: "
encoded_string = encrypt(plain_text)
print("The encoded string is : ", encoded_string)

# Decryption
decrypted_text = decrypt(encoded_string)
print("The decrypted text is : ", decrypted_text)

