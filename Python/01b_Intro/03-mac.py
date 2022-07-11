import base64
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA3_256
import json

if __name__ == '__main__':
    msg = b'This is the message used in input'

    #secret = get_random_bytes(32)
    secret = b'sfdfddfdsdsgteeteteerr'

    hmac = HMAC.new(secret, digestmod=SHA3_256)

    hmac.update(msg[:5])
    hmac.update(msg[5:])

    print(hmac.hexdigest())

    obj = json.dumps({'message': msg.decode(),'MAC': base64.b64encode(hmac.digest()).decode()})

    print(obj)

    b64_obj = json.loads(obj)
    hmac_verifier = HMAC.new(secret, digestmod=SHA3_256)

    hmac_verifier.update(b64_obj['message'].encode())

    mac = bytearray(base64.b64decode(b64_obj['MAC'].encode()))
    mac[0] = 0
    
    try:
        hmac_verifier.verify(mac)
        print("Authentic message.")
    except ValueError:
        print("Wrong message or secret")
