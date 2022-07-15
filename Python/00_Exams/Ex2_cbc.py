# Two users, Alice and Bob, who want to exchange messages encrypted with AES-128 in 
# CBC mode, have agreed on a custom padding method. The padding function, if the last
# block contains the RESIDUE_BYTES, fills the block with the following operations:
#
# RESIDUE_BYTES || (1 byte) length of RESIDUE_BYTES || the last 16-1-length of RESIDUE_BYTES of the IV
#
# For instance, if the IV is (as hex string) "ABCDEF0123456789"
# and the RESIDUE_BYTES (i.e., the part of the last block to pad) are "HELLO"
# the last block is completed as
# "HELLO"+"5"+"0123456789"
# "5" because the length of RESIDUE_BYTES is 5 bytes,
# "0123456789" because these are the last 10 bytes (16-5-1) bytes of the IV
# The code of the padding function is reported here:

def pad(msg, iv):
    residue_len = len(msg) % AES.block_size
    if residue_len == 0: #if the last block is full, add an entire block
        residue_len = AES.block_size
        
    padded_msg = msg
    padded_msg += residue_len.to_bytes(1.byteorder='big')
    if residue_len < AES.block_size-1:
        bytes_to_add = AES.block_size - 1 - residue_len
        padded_msg += iv[-bytes_to_add:]
    return padded_msg

# Bob has set up a server that receives IV and ciphertext and stores the decrypted messages
# locally. The server sends error messages to the sender in case of decryption issues. If the
# padding is incorrect, it returns the bytes b'wrongPAD'. To relevant part of the server's code is

# You have sniffed a ciphertext that Alice has sent Bob, write a program in python to GUESS the 
# last three bytes of the last block of the ciphertext, which can be accessed, together with the used IV as:

from mysecrets import exam_july21_iv as iv
from mysecrets import exam_july21_ciphertext as ciphertext

def num_blocks(ciphertext, block_size):
    return math.ceil(len(ciphertext)/block_size)
    
def guess_byte(p,c,ciphertext,block_size):
    # p and c must have the same length
    padding_value = iv[block_size - len(p) - 1]
    
    print("pad="+str(padding_value))
    n = num_blocks(ciphertext,block_size)
    print("n="+str(n))
    current_byte_index= len(ciphertext)-1 -block_size - len(p)
    print("current="+str(current_byte_index))

    # print(p)
    # print(c)
    plain = b'\x00'
    for i in range(0,256):
        # print(i)
        ca = bytearray()
        ca += ciphertext[:current_byte_index]
        ca += i.to_bytes(1,byteorder='big')

        # print(ca)
        for x in p:
            ca += (x ^ padding_value).to_bytes(1,byteorder='big')
        # print(ca)
        ca += get_nth_block(ciphertext,n-1,block_size)
        # print(ca)
        # print("          "+str(ciphertext))

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(ca)
        response = server.recv(1024)

        # print(response)

        if response == b'OKPAD':
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i
            plain = bytes([p_prime ^ ciphertext[current_byte_index]])
            if plain == bytes(padding_value): #this is not sufficient in the general case, onyl wokrs for the last byte and not always
                continue
            # print(p_prime)
            # print(ciphertext[current_byte_index])
            # print(p_prime ^ ciphertext[current_byte_index])
            c.insert(0,i)
            p.insert(0,p_prime)
            # print(p)
            # print(type(p_prime))
            # x= bytes([p_prime ^ ciphertext[current_byte_index]])
            # break


    return plain    
    
if __name__ == '__main__':
    n = num_blocks(ciphertext,AES.block_size)
    plaintext = bytearray()

    c = []
    p = []

    for j in range(AES.block_size-2,AES.block_size):
        plaintext[0:0] = guess_byte(p,c,ciphertext,AES.block_size)
        print(plaintext)