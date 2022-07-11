# prefix + input + postfix
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from myconfig import HOST, PORT

from pwn import *
from Crypto.Cipher import AES

server = remote(HOST, PORT)

#input_message = b"This is the messagee" # 20 bytes = 64, >20 bytes = 80
input_message = b"A"*48 # c3 blocks
server.send(input_message)
ciphertext = server.recv(1024)

print(ciphertext)
print("Len:" + str(len(ciphertext)))

for i in range(len(ciphertext)//AES.block_size):
    print(ciphertext[i*AES.block_size:(i+1)*AES.block_size])

if ciphertext[32:48] == ciphertext[48:64]:
    print("ECB")
else:
    print("CBC")