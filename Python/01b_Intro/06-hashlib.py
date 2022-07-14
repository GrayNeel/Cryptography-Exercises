import hashlib, hmac
from Crypto.Random import get_random_bytes

if __name__ == '__main__':
    dig_generator = hashlib.sha256()
    dig_generator.update(b'First chuck of data')
    dig_generator.update(b'Second chuck of data')

    print(dig_generator.hexdigest())

    secret = get_random_bytes(32)
    mac_generator = hmac.new(secret, b'message to hash', hashlib.sha256)

    hmac_sender = mac_generator.hexdigest()

    # ------------------------

    mac_gen_rec = hmac.new(secret, b'message to hash', hashlib.sha256)
    hmac_ver = mac_gen_rec.hexdigest()

    if hmac.compare_digest(hmac_sender, hmac_ver):
        print("Everything is ok.")
    else:
        print("Error.")
