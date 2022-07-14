from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

if __name__ == '__main__':
    password = b'WeakP4sswd'

    key = scrypt(password, get_random_bytes(16), 16, N=2**20, r=8, p=1)
    print(key)
