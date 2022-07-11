from hashlib import sha256
from Crypto.Hash import SHA256

if __name__ == '__main__':
    hash_generator = SHA256.new()

    hash_generator.update(b'text to hash')
    hash_generator.update(b' even more text')

    print(hash_generator.hexdigest())
    print(hash_generator.digest())

    hash_generator = SHA256.new(data=b'initial bytes')
    hash_generator.update(b'text to hash')
    hash_generator.update(b' even more text')

    print(hash_generator.hexdigest())
    print(hash_generator.digest())