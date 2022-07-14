from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
import base64

if __name__ == '__main__':
    
    plaintext = b'This is the secret message...'
    
    key = get_random_bytes(ChaCha20.key_size)
    
    cipher = ChaCha20.new(key = key) # nonce is not specified
    
    ciphertext = cipher.encrypt(plaintext)
    
    print("Ciphertext=" + base64.b)
    