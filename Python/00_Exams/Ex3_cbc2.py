# Mallory sniffed a communication between a client and a server.

# The data sent to the server are 48 bytes long. They are, according to the result of
# some mathematical tool, indistinguishable from random numbers. She correctly guessed
# it is an AES-based ciphertext. These data are stored in a Python module and imported
# as

from mysniffeddata import ciphertext

# When Mallory sent again the server the ciphertext, which answers any request from
# the Internet, the response of the server is composed of four bytes:
# "\x00\x00\x00\x00"
# which have been stored as 

from mydata import correct_server_answer

# Mallory tried to change some random bits of the ciphertext and resent the whole
# ciphertext to the server

# She observed the following behaviour:

# When changing 1 bit in ciphertext[32:], the answer of the server is "\x01\x00\x00\x00".
# She stored this answer to be obtained as 

from mydata import wrong_server_answer

# When changing 1 bit in ciphertext[:16], the answer of the server is "\x00\x00\x00\x00"
# When changing 1 bit in ciphertext[16:24], the answer of the server is "\x00\x00\x00\x00"
# When changing 1 bit in ciphertext[24:32], the answer of the server is "\x01\x00\x00\x00"

# What can Mallory guess about the first 16 bytes of the sniffed data?
# They may be the IV of the ciphertext.

# What can Mallory guess about the last 16 bytes of the sniffed data?
# They can contain some text and then some padding if the plaintext is not multiple of a block

# Can you guess the size of the plaintext?
# The size can be 48 bytes - 16 bytes for the IV - padding if any = 32 bytes at most, 16 bytes minimum

# What kind of attack can Mallory try to decrypt the ciphertext?
# She can try the CBC Padding Oracle attack.

# Write an implementation to decrypt ciphertext[16:32]

def num_blocks(ciphertext, block_size):
    return math.ceil(len(ciphertext)/block_size)
    
def get_nth_block(ciphertext, n, block_size):
    return ciphertext[(n)*block_size:(n+1)*block_size]
    
def guess_byte(p,c,ciphertext,block_size):
    # p and c must have the same length
    padding_value = len(p)+1
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

        if response == correct_server_answer:
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i
            plain = bytes([p_prime ^ ciphertext[current_byte_index]])
            if plain == b'\x01': #this is not sufficient in the general case, onyl wokrs for the last byte and not always
                continue
            c.insert(0,i)
            p.insert(0,p_prime)


    return 

if __name__ == '__main__':
    n = num_blocks(ciphertext,AES.block_size)
    plaintext = bytearray()
    
    c = []
    p = []
    
    # Pass from 0 to 32 bytes of ciphertext
    for j in range(0,AES.block_size):
        plaintext[0:0] = guess_byte(p,c,ciphertext[:32],AES.block_size)
        print(plaintext)
    