from Crypto.Hash import SHA3_256

if __name__ == '__main__':
    hash_generator = SHA3_256.new()

    with open(__file__) as f_input:
        hash_generator.update(f_input.read().encode())

    print(hash_generator.hexdigest())
    print(hash_generator.digest())
    